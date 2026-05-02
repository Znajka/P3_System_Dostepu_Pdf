package com.p3.dostepu.application.service;

import java.time.ZonedDateTime;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.p3.dostepu.api.dto.AccessGrantRequest;
import com.p3.dostepu.api.dto.AccessGrantResponse;
import com.p3.dostepu.application.exception.ConflictException;
import com.p3.dostepu.application.exception.ResourceNotFoundException;
import com.p3.dostepu.application.exception.UnauthorizedException;
import com.p3.dostepu.domain.entity.AccessAction;
import com.p3.dostepu.domain.entity.AccessEventLog;
import com.p3.dostepu.domain.entity.AccessGrant;
import com.p3.dostepu.domain.entity.AccessResult;
import com.p3.dostepu.domain.entity.Document;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.entity.UserRole;
import com.p3.dostepu.domain.repository.AccessEventLogRepository;
import com.p3.dostepu.domain.repository.AccessGrantRepository;
import com.p3.dostepu.domain.repository.DocumentRepository;
import com.p3.dostepu.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Updated AccessGrantService with integrated AuditLogService.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccessGrantService {

  private final AccessGrantRepository grantRepository;
  private final DocumentRepository documentRepository;
  private final UserRepository userRepository;
  private final AccessEventLogRepository auditLogRepository;
  private final AuditLogService auditLogService; // ADD THIS

  /**
   * Grant document access to a user with expiration time.
   *
   * @param documentId document UUID
   * @param request grant request (granteeUserId, expiresAt, note)
   * @param grantedBy authenticated user (OWNER or ADMIN)
   * @param clientIp client IP address for audit
   * @return grant response with grant ID and metadata
   * @throws ResourceNotFoundException if document or grantee user not found
   * @throws UnauthorizedException if grantedBy is not OWNER or ADMIN
   * @throws ConflictException if active grant already exists for grantee
   */
  @Transactional
  public AccessGrantResponse grantAccess(UUID documentId, AccessGrantRequest request,
      User grantedBy, String clientIp) {

    try {
      // Step 1: Validate document exists and not deleted
      Document document = documentRepository.findByIdAndDeletedAtNull(documentId)
          .orElseThrow(() -> new ResourceNotFoundException(
              "Document not found: " + documentId));

      // Step 2: Authorize grantedBy (OWNER or ADMIN)
      UUID granteeUserId = UUID.fromString(request.getGranteeUserId());
      if (!isAuthorizedToGrant(document, grantedBy)) {
        logAccessEvent(grantedBy.getId(), documentId, AccessAction.GRANT,
            AccessResult.FAILURE, clientIp, "Not authorized to grant access");
        throw new UnauthorizedException(
            "Only document OWNER or ADMIN can grant access");
      }

      // Step 3: Validate grantee user exists and is active
      User granteeUser = userRepository.findByIdAndActiveTrue(granteeUserId)
          .orElseThrow(() -> new ResourceNotFoundException(
              "Grantee user not found or inactive: " + granteeUserId));

      // Step 4: Validate expiration time is in the future
      ZonedDateTime now = ZonedDateTime.now();
      if (!request.getExpiresAt().isAfter(now)) {
        logAccessEvent(grantedBy.getId(), documentId, AccessAction.GRANT,
            AccessResult.FAILURE, clientIp, "Expiration time is not in the future");
        throw new IllegalArgumentException(
            "Expiration time must be in the future");
      }

      // Step 5: Check for existing active grant (prevent overlapping grants)
      Integer activeCount = grantRepository.countActiveGrants(documentId, granteeUserId,
          now);
      if (activeCount != null && activeCount > 0) {
        logAccessEvent(grantedBy.getId(), documentId, AccessAction.GRANT,
            AccessResult.FAILURE, clientIp,
            "Active grant already exists for this grantee");
        throw new ConflictException(
            "Active grant already exists for this grantee and document");
      }

      // Step 6: Create AccessGrant entity
      AccessGrant grant = AccessGrant.builder()
          .document(document)
          .granteeUser(granteeUser)
          .grantedByUser(grantedBy)
          .expiresAt(request.getExpiresAt())
          .revoked(false)
          .build();

      grant = grantRepository.save(grant);

      // LOG AUDIT EVENT (SUCCESS) - UPDATED
      auditLogService.logGrant(grantedBy.getId(), granteeUser.getId(), documentId,
          request.getExpiresAt(), clientIp, null, true, null);

      return AccessGrantResponse.builder()
          .grantId(grant.getId())
          .documentId(grant.getDocument().getId())
          .granteeUserId(grant.getGranteeUser().getId())
          .grantedBy(grant.getGrantedByUser().getId())
          .expiresAt(grant.getExpiresAt())
          .createdAt(grant.getCreatedAt())
          .build();

    } catch (ConflictException | UnauthorizedException | ResourceNotFoundException e) {
      throw e;
    } catch (Exception e) {
      log.error("Grant access failed: {}", e.getMessage(), e);
      // LOG AUDIT EVENT (FAILURE) - UPDATED
      auditLogService.logGrant(grantedBy.getId(),
          UUID.fromString(request.getGranteeUserId()), documentId,
          request.getExpiresAt(), clientIp, null, false, e.getMessage());
      throw e;
    }
  }

  /**
   * Revoke document access for a user.
   *
   * @param documentId document UUID
   * @param granteeUserId user to revoke access from
   * @param revokedBy authenticated user (OWNER or ADMIN)
   * @param reason revocation reason (optional, for audit)
   * @param clientIp client IP address for audit
   * @return grant response with revoke metadata
   */
  @Transactional
  public AccessGrantResponse revokeAccess(UUID documentId, UUID granteeUserId,
      User revokedBy, String reason, String clientIp) {

    try {
      // Step 1: Validate document exists
      Document document = documentRepository.findByIdAndDeletedAtNull(documentId)
          .orElseThrow(() -> new ResourceNotFoundException(
              "Document not found: " + documentId));

      // Step 2: Authorize revokedBy (OWNER or ADMIN)
      if (!isAuthorizedToGrant(document, revokedBy)) {
        logAccessEvent(revokedBy.getId(), documentId, AccessAction.REVOKE,
            AccessResult.FAILURE, clientIp, "Not authorized to revoke access");
        throw new UnauthorizedException(
            "Only document OWNER or ADMIN can revoke access");
      }

      // Step 3: Find active grant
      ZonedDateTime now = ZonedDateTime.now();
      AccessGrant grant = grantRepository
          .findByDocumentIdAndGranteeUserIdAndRevokedFalseAndExpiresAtAfter(
              documentId, granteeUserId, now)
          .orElseThrow(() -> new ResourceNotFoundException(
              "Active grant not found for document and grantee"));

      // Step 4: Revoke grant
      grant.revoke(revokedBy, reason);
      grant = grantRepository.save(grant);

      // LOG AUDIT EVENT (SUCCESS) - UPDATED
      auditLogService.logRevoke(revokedBy.getId(), granteeUserId, documentId, reason,
          clientIp, null);

      return AccessGrantResponse.builder()
          .grantId(grant.getId())
          .documentId(grant.getDocument().getId())
          .granteeUserId(grant.getGranteeUser().getId())
          .grantedBy(grant.getGrantedByUser().getId())
          .expiresAt(grant.getExpiresAt())
          .createdAt(grant.getCreatedAt())
          .build();

    } catch (UnauthorizedException | ResourceNotFoundException e) {
      throw e;
    } catch (Exception e) {
      log.error("Revoke access failed: {}", e.getMessage(), e);
      throw e;
    }
  }

  /**
   * Check if user is authorized to grant/revoke access.
   * Authorization: user is document OWNER or has ADMIN role.
   */
  private boolean isAuthorizedToGrant(Document document, User user) {
    boolean isOwner = document.getOwner().getId().equals(user.getId());
    boolean isAdmin = user.getRoles().contains(UserRole.ADMIN);
    return isOwner || isAdmin;
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