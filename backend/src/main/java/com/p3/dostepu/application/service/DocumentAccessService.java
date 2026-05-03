package com.p3.dostepu.application.service;

import java.time.ZonedDateTime;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.p3.dostepu.api.dto.OpenTicketResponse;
import com.p3.dostepu.application.exception.ResourceNotFoundException;
import com.p3.dostepu.application.exception.UnauthorizedException;
import com.p3.dostepu.domain.entity.AccessAction;
import com.p3.dostepu.domain.entity.AccessEventLog;
import com.p3.dostepu.domain.entity.AccessResult;
import com.p3.dostepu.domain.entity.Document;
import com.p3.dostepu.domain.entity.TicketNonce;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.entity.UserRole;
import com.p3.dostepu.domain.repository.AccessEventLogRepository;
import com.p3.dostepu.domain.repository.AccessGrantRepository;
import com.p3.dostepu.domain.repository.DocumentRepository;
import com.p3.dostepu.domain.repository.TicketNonceRepository;
import com.p3.dostepu.security.jwt.JwtProvider;
import com.p3.dostepu.infrastructure.security.RateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Updated DocumentAccessService with integrated AuditLogService.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DocumentAccessService {

  private final DocumentRepository documentRepository;
  private final AccessGrantRepository grantRepository;
  private final TicketNonceRepository ticketNonceRepository;
  private final AccessEventLogRepository auditLogRepository;
  private final RateLimiterService rateLimiterService;
  private final JwtProvider jwtProvider;
  private final AuditLogService auditLogService; // ADD THIS

  @Value("${app.document.ticket-ttl-seconds:60}")
  private Integer ticketTtlSeconds;

  /**
   * Issue a single-use streaming ticket for document access.
   * Flow:
   *   1. Check user not locked (rate-limit)
   *   2. Validate document exists
   *   3. Check valid ACCESS_GRANT (not expired, not revoked)
   *   4. Generate unique nonce (JTI)
   *   5. Create JWT ticket (scoped to doc, user, pdf-microservice)
   *   6. Persist nonce for replay prevention
   *   7. Log open_attempt (success or failure)
   *   8. Return ticket or error
   *
   * @param documentId document UUID
   * @param user authenticated user
   * @param clientIp client IP for audit
   * @return OpenTicketResponse with JWT ticket (60-second TTL)
   */
  @Transactional
  public OpenTicketResponse issueAccessTicket(UUID documentId, User user,
      String clientIp) {

    try {
      // Step 1: Check rate limit FIRST
      rateLimiterService.checkRateLimit(user.getId(), "open-ticket");

      // Step 2: Validate document exists and not deleted
      Document document = documentRepository.findByIdAndDeletedAtNull(documentId)
          .orElseThrow(() -> new ResourceNotFoundException(
              "Document not found: " + documentId));

      // Step 3: Check access grant (valid and not expired)
      ZonedDateTime now = ZonedDateTime.now();
      boolean hasValidGrant = grantRepository
          .findByDocumentIdAndGranteeUserIdAndRevokedFalseAndExpiresAtAfter(
              documentId, user.getId(), now)
          .isPresent();

      // Step 4: Check if user is ADMIN or OWNER (bypass grant check)
      boolean isAuthorized = hasValidGrant
          || document.getOwner().getId().equals(user.getId())
          || user.getRoles().contains(UserRole.ADMIN);

      if (!isAuthorized) {
        rateLimiterService.recordFailedAttempt(user.getId(), "open-ticket");
        logAccessEvent(user.getId(), documentId, AccessAction.OPEN_ATTEMPT,
            AccessResult.FAILURE, clientIp, "No valid grant");
        throw new UnauthorizedException(
            "Access denied: no valid grant for this document");
      }

      // Step 5: Generate unique nonce (JTI)
      String nonce = UUID.randomUUID().toString();

      // Step 6: Create JWT ticket WITH IP PINNING
      String ticket = jwtProvider.generateDocumentAccessTicket(
          user.getId().toString(),
          documentId.toString(),
          nonce,
          clientIp,  // IP-pinning: include client IP in ticket
          ticketTtlSeconds
      );

      log.info(
          "Generated access ticket with IP pinning: user={}, document={}, "
              + "clientIp={}, ttlSeconds={}",
          user.getId(), documentId, clientIp, ticketTtlSeconds
      );

      // Step 7: Persist nonce for replay prevention (mark used after FastAPI validates)
      ZonedDateTime ticketExpiry = now.plusSeconds(ticketTtlSeconds);
      TicketNonce ticketNonce = TicketNonce.builder()
          .nonce(nonce)
          .document(document)
          .user(user)
          .used(false)
          .expiresAt(ticketExpiry)
          .build();

      ticketNonceRepository.save(ticketNonce);

      // LOG AUDIT EVENT (SUCCESS) - UPDATED
      auditLogService.logOpenAttempt(user.getId(), documentId, clientIp, null, true,
          null);

      // Step 9: Reset failed attempts on SUCCESS
      rateLimiterService.resetFailedAttempts(user.getId());

      return OpenTicketResponse.builder()
          .ticket(ticket)
          .ticketId(nonce)
          .expiresAt(ticketExpiry)
          .issuedAt(now)
          .usage(OpenTicketResponse.Usage.builder()
              .singleUse(true)
              .aud("pdf-microservice")
              .documentId(documentId.toString())
              .userId(user.getId().toString())
              .build())
          .build();

    } catch (RateLimitExceededException e) {
      // Log failure and increment counter
      rateLimiterService.recordFailedAttempt(user.getId(), "open-ticket");
      auditLogService.logOpenAttempt(user.getId(), documentId, clientIp, null,
          false, e.getMessage());
      throw e;

    } catch (Exception e) {
      // Log other failures
      rateLimiterService.recordFailedAttempt(user.getId(), "open-ticket");
      auditLogService.logOpenAttempt(user.getId(), documentId, clientIp, null,
          false, e.getMessage());
      throw e;
    }
  }

  /**
   * Mark ticket as used (called by FastAPI after validating and decrypting).
   * Prevents replay attacks by marking nonce as consumed.
   *
   * @param nonce ticket nonce (JTI)
   * @param userId user UUID
   * @return true if marked successfully, false if already used or expired
   */
  @Transactional
  public boolean markTicketAsUsed(String nonce, UUID userId) {
    TicketNonce ticketNonce = ticketNonceRepository
        .findByNonceAndUsedFalseAndExpiresAtAfter(nonce, ZonedDateTime.now())
        .orElse(null);

    if (ticketNonce == null) {
      log.warn("Ticket not found or already used: {}", nonce);
      return false;
    }

    if (!ticketNonce.getUser().getId().equals(userId)) {
      log.warn("Ticket user mismatch: expected={}, actual={}", userId,
          ticketNonce.getUser().getId());
      return false;
    }

    ticketNonce.markUsed();
    ticketNonceRepository.save(ticketNonce);
    log.info("Marked ticket as used: {}", nonce);
    return true;
  }

  /**
   * Log access event to audit trail.
   */
  private void logAccessEvent(UUID userId, UUID documentId, AccessAction action,
      AccessResult result, String clientIp, String reason) {
    try {
      AccessEventLog event = AccessEventLog.builder()
          .user(userId != null ? new User() {
            {
              setId(userId);
            }
          } : null)
          .document(documentId != null ? new Document() {
            {
              setId(documentId);
            }
          } : null)
          .action(action)
          .result(result)
          .ipAddress(clientIp)
          .reason(reason)
          .timestampUtc(ZonedDateTime.now())
          .build();

      auditLogRepository.save(event);
    } catch (Exception e) {
      log.error("Failed to log access event: {}", e.getMessage());
    }
  }
}