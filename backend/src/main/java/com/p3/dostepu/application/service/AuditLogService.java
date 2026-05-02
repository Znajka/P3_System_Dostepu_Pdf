package com.p3.dostepu.application.service;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.p3.dostepu.domain.entity.AccessAction;
import com.p3.dostepu.domain.entity.AccessEventLog;
import com.p3.dostepu.domain.entity.AccessResult;
import com.p3.dostepu.domain.entity.Document;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.repository.AccessEventLogRepository;
import com.p3.dostepu.infrastructure.audit.AccessEventLogSpecification;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.jpa.domain.Specification;

/**
 * AuditLogService: centralized service for logging access events.
 * Per CONTRIBUTING.md Logging & Auditing:
 *   - APPEND-ONLY: no updates or deletes after insertion
 *   - Records: timestamp (UTC), user_id, document_id, action, result, IP, reason
 *   - Used for compliance, breach investigation, rate-limit decisions
 * Actions: upload, grant, revoke, open_attempt, stream_start, stream_end
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {

  private final AccessEventLogRepository logRepository;
  private final ObjectMapper objectMapper;

  /**
   * Log document upload event.
   *
   * @param userId user performing upload
   * @param documentId uploaded document
   * @param fileSizeBytes file size in bytes
   * @param clientIp client IP address
   * @param userAgent user agent string
   * @param success true if upload succeeded
   * @param reason failure reason (if applicable)
   */
  @Transactional
  public void logUpload(UUID userId, UUID documentId, Long fileSizeBytes, String clientIp,
      String userAgent, boolean success, String reason) {
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
        .action(AccessAction.UPLOAD)
        .result(success ? AccessResult.SUCCESS : AccessResult.FAILURE)
        .ipAddress(clientIp)
        .userAgent(userAgent)
        .reason(reason)
        .metadata(serializeMetadata("file_size_bytes", fileSizeBytes))
        .timestampUtc(ZonedDateTime.now())
        .build();

    logRepository.save(event);
    log.info(
        "Logged upload: user={}, document={}, status={}, size={}",
        userId, documentId, (success ? "SUCCESS" : "FAILURE"), fileSizeBytes);
  }

  /**
   * Log document access grant event.
   *
   * @param grantedByUserId user granting access
   * @param grantedToUserId user receiving access
   * @param documentId document being granted
   * @param expiresAt expiration timestamp
   * @param clientIp client IP address
   * @param userAgent user agent string
   * @param success true if grant succeeded
   * @param reason failure reason (if applicable)
   */
  @Transactional
  public void logGrant(UUID grantedByUserId, UUID grantedToUserId, UUID documentId,
      ZonedDateTime expiresAt, String clientIp, String userAgent, boolean success,
      String reason) {
    AccessEventLog event = AccessEventLog.builder()
        .user(grantedByUserId != null ? new User() {
          {
            setId(grantedByUserId);
          }
        } : null)
        .document(documentId != null ? new Document() {
          {
            setId(documentId);
          }
        } : null)
        .action(AccessAction.GRANT)
        .result(success ? AccessResult.SUCCESS : AccessResult.FAILURE)
        .ipAddress(clientIp)
        .userAgent(userAgent)
        .reason(reason)
        .metadata(serializeMetadata("granted_to_user", grantedToUserId,
            "expires_at", expiresAt))
        .timestampUtc(ZonedDateTime.now())
        .build();

    logRepository.save(event);
    log.info(
        "Logged grant: granted_by={}, granted_to={}, document={}, status={}, expires={}",
        grantedByUserId, grantedToUserId, documentId, (success ? "SUCCESS" : "FAILURE"),
        expiresAt);
  }

  /**
   * Log document access revoke event.
   *
   * @param revokedByUserId user revoking access
   * @param revokedFromUserId user losing access
   * @param documentId document being revoked
   * @param revokeReason reason for revocation
   * @param clientIp client IP address
   * @param userAgent user agent string
   */
  @Transactional
  public void logRevoke(UUID revokedByUserId, UUID revokedFromUserId, UUID documentId,
      String revokeReason, String clientIp, String userAgent) {
    AccessEventLog event = AccessEventLog.builder()
        .user(revokedByUserId != null ? new User() {
          {
            setId(revokedByUserId);
          }
        } : null)
        .document(documentId != null ? new Document() {
          {
            setId(documentId);
          }
        } : null)
        .action(AccessAction.REVOKE)
        .result(AccessResult.SUCCESS)
        .ipAddress(clientIp)
        .userAgent(userAgent)
        .reason(revokeReason)
        .metadata(serializeMetadata("revoked_from_user", revokedFromUserId))
        .timestampUtc(ZonedDateTime.now())
        .build();

    logRepository.save(event);
    log.info(
        "Logged revoke: revoked_by={}, revoked_from={}, document={}, reason={}",
        revokedByUserId, revokedFromUserId, documentId, revokeReason);
  }

  /**
   * Log document open attempt event (ticket issuance).
   *
   * @param userId user attempting to open
   * @param documentId document being opened
   * @param clientIp client IP address
   * @param userAgent user agent string
   * @param success true if attempt succeeded
   * @param reason failure reason (if applicable)
   */
  @Transactional
  public void logOpenAttempt(UUID userId, UUID documentId, String clientIp,
      String userAgent, boolean success, String reason) {
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
        .action(AccessAction.OPEN_ATTEMPT)
        .result(success ? AccessResult.SUCCESS : AccessResult.FAILURE)
        .ipAddress(clientIp)
        .userAgent(userAgent)
        .reason(reason)
        .timestampUtc(ZonedDateTime.now())
        .build();

    logRepository.save(event);
    log.info(
        "Logged open_attempt: user={}, document={}, status={}, reason={}",
        userId, documentId, (success ? "SUCCESS" : "FAILURE"), reason);
  }

  /**
   * Log stream start event (FastAPI begins streaming decrypted PDF).
   *
   * @param userId user streaming
   * @param documentId document being streamed
   * @param ticketNonce ticket nonce (for correlating events)
   * @param clientIp client IP address
   * @param userAgent user agent string
   */
  @Transactional
  public void logStreamStart(UUID userId, UUID documentId, String ticketNonce,
      String clientIp, String userAgent) {
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
        .action(AccessAction.STREAM_START)
        .result(AccessResult.SUCCESS)
        .ipAddress(clientIp)
        .userAgent(userAgent)
        .metadata(serializeMetadata("ticket_nonce", ticketNonce))
        .timestampUtc(ZonedDateTime.now())
        .build();

    logRepository.save(event);
    log.info(
        "Logged stream_start: user={}, document={}, nonce={}",
        userId, documentId, ticketNonce);
  }

  /**
   * Log stream end event (FastAPI finishes streaming decrypted PDF).
   *
   * @param userId user streaming
   * @param documentId document being streamed
   * @param ticketNonce ticket nonce (for correlating events)
   * @param bytesStreamed total bytes streamed
   * @param success true if stream completed successfully
   * @param reason failure reason (if applicable)
   * @param clientIp client IP address
   * @param userAgent user agent string
   */
  @Transactional
  public void logStreamEnd(UUID userId, UUID documentId, String ticketNonce,
      Long bytesStreamed, boolean success, String reason, String clientIp,
      String userAgent) {
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
        .action(AccessAction.STREAM_END)
        .result(success ? AccessResult.SUCCESS : AccessResult.FAILURE)
        .ipAddress(clientIp)
        .userAgent(userAgent)
        .reason(reason)
        .metadata(serializeMetadata("ticket_nonce", ticketNonce,
            "bytes_streamed", bytesStreamed))
        .timestampUtc(ZonedDateTime.now())
        .build();

    logRepository.save(event);
    log.info(
        "Logged stream_end: user={}, document={}, nonce={}, status={}, bytes={}",
        userId, documentId, ticketNonce, (success ? "SUCCESS" : "FAILURE"),
        bytesStreamed);
  }

  /**
   * Query access event logs with filters (pagination, date range, action, result).
   *
   * @param userId optional filter by user
   * @param documentId optional filter by document
   * @param action optional filter by action
   * @param result optional filter by result
   * @param fromTimestamp optional filter from timestamp (inclusive)
   * @param toTimestamp optional filter to timestamp (inclusive)
   * @param page page number (0-indexed)
   * @param limit items per page
   * @return paginated access event logs
   */
  @Transactional(readOnly = true)
  public Page<AccessEventLog> queryEvents(UUID userId, UUID documentId,
      AccessAction action, AccessResult result, ZonedDateTime fromTimestamp,
      ZonedDateTime toTimestamp, Integer page, Integer limit) {

    Pageable pageable = PageRequest.of(page, limit,
        Sort.by(Sort.Direction.DESC, "timestampUtc"));

    Specification<AccessEventLog> spec =
        AccessEventLogSpecification.withFilters(userId, documentId, action, result,
            fromTimestamp, toTimestamp);

    return logRepository.findAll(spec, pageable);
  }

  /**
   * Count access events with filters.
   *
   * @param userId optional filter by user
   * @param documentId optional filter by document
   * @param action optional filter by action
   * @param result optional filter by result
   * @param fromTimestamp optional filter from timestamp
   * @param toTimestamp optional filter to timestamp
   * @return count of matching events
   */
  @Transactional(readOnly = true)
  public long countEvents(UUID userId, UUID documentId, AccessAction action,
      AccessResult result, ZonedDateTime fromTimestamp, ZonedDateTime toTimestamp) {

    Specification<AccessEventLog> spec =
        AccessEventLogSpecification.withFilters(userId, documentId, action, result,
            fromTimestamp, toTimestamp);

    return logRepository.count(spec);
  }

  /**
   * Get latest failed attempts for a user (for rate-limit analysis).
   *
   * @param userId user UUID
   * @param minutesBack number of minutes to look back
   * @return list of failed open_attempt events
   */
  @Transactional(readOnly = true)
  public List<AccessEventLog> getFailedAttempts(UUID userId, Integer minutesBack) {
    ZonedDateTime cutoffTime = ZonedDateTime.now().minusMinutes(minutesBack);

    Specification<AccessEventLog> spec =
        AccessEventLogSpecification.withFilters(userId, null, AccessAction.OPEN_ATTEMPT,
            AccessResult.FAILURE, cutoffTime, null);

    return logRepository.findAll(spec, Sort.by(Sort.Direction.DESC, "timestampUtc"));
  }

  /**
   * Get access history for a specific document.
   *
   * @param documentId document UUID
   * @param daysBack number of days to look back
   * @return list of events for document
   */
  @Transactional(readOnly = true)
  public List<AccessEventLog> getDocumentHistory(UUID documentId, Integer daysBack) {
    ZonedDateTime cutoffTime = ZonedDateTime.now().minusDays(daysBack);

    Specification<AccessEventLog> spec =
        AccessEventLogSpecification.withFilters(null, documentId, null, null,
            cutoffTime, null);

    return logRepository.findAll(spec, Sort.by(Sort.Direction.DESC, "timestampUtc"));
  }

  /**
   * Serialize metadata to JSON string.
   */
  private String serializeMetadata(Object... keysAndValues) {
    try {
      if (keysAndValues.length % 2 != 0) {
        log.warn("Metadata keys and values must be in pairs");
        return null;
      }

      Map<String, Object> metadata = new java.util.LinkedHashMap<>();
      for (int i = 0; i < keysAndValues.length; i += 2) {
        metadata.put(keysAndValues[i].toString(), keysAndValues[i + 1]);
      }

      return objectMapper.writeValueAsString(metadata);
    } catch (Exception e) {
      log.error("Failed to serialize metadata: {}", e.getMessage());
      return null;
    }
  }
}