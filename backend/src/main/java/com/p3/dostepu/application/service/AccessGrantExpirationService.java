package com.p3.dostepu.application.service;

import java.time.ZonedDateTime;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.p3.dostepu.domain.entity.AccessGrant;
import com.p3.dostepu.domain.entity.AccessAction;
import com.p3.dostepu.domain.entity.AccessResult;
import com.p3.dostepu.domain.entity.AccessEventLog;
import com.p3.dostepu.domain.repository.AccessGrantRepository;
import com.p3.dostepu.domain.repository.AccessEventLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service for automatically revoking expired ACCESS_GRANT records.
 * Per CONTRIBUTING.md:
 *   - Documents inaccessible after expiration
 *   - Log all operations (revoke)
 *
 * Scheduled to run every 5 minutes (configurable).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccessGrantExpirationService {

  private final AccessGrantRepository grantRepository;
  private final AccessEventLogRepository auditLogRepository;

  @Value("${app.scheduled.grant-expiration-enabled:true}")
  private Boolean expirationCheckEnabled;

  @Value("${app.scheduled.grant-expiration-interval-seconds:300}")
  private Integer expirationCheckIntervalSeconds;

  private volatile Long lastExecutionTime = 0L;
  private volatile Integer lastRevokedCount = 0;

  /**
   * Scheduled task: revoke expired ACCESS_GRANT records.
   * Runs every 5 minutes (300 seconds) by default.
   * Configurable via application.yml: app.scheduled.grant-expiration-interval-seconds
   *
   * Per CONTRIBUTING.md Security Requirements:
   *   - Documents inaccessible after expiration
   *   - All operations logged to ACCESS_EVENT_LOG
   */
  @Scheduled(fixedRateString = "${app.scheduled.grant-expiration-interval-seconds:300}000",
      initialDelayString = "${app.scheduled.grant-expiration-initial-delay-seconds:60}000")
  @Transactional
  public void revokeExpiredGrants() {
    try {
      if (!expirationCheckEnabled) {
        log.debug("Access grant expiration check is disabled");
        return;
      }

      long startTime = System.currentTimeMillis();
      ZonedDateTime now = ZonedDateTime.now();

      log.info("Starting scheduled task: revoke expired ACCESS_GRANT records (threshold: {})",
          now);

      // Step 1: Query for expired, non-revoked grants
      List<AccessGrant> expiredGrants = grantRepository.findExpiredAndNotRevokedGrants(now);

      if (expiredGrants.isEmpty()) {
        log.debug("No expired grants found");
        lastExecutionTime = System.currentTimeMillis();
        lastRevokedCount = 0;
        return;
      }

      log.info("Found {} expired ACCESS_GRANT records", expiredGrants.size());

      // Step 2: Revoke each expired grant
      for (AccessGrant grant : expiredGrants) {
        try {
          revokeExpiredGrant(grant);
        } catch (Exception e) {
          log.error(
              "Failed to revoke expired grant: grantId={}, documentId={}, grantee={}",
              grant.getId(), grant.getDocument().getId(),
              grant.getGranteeUser().getId(), e
          );
          // Continue processing other grants
        }
      }

      long executionTime = System.currentTimeMillis() - startTime;
      lastExecutionTime = executionTime;
      lastRevokedCount = expiredGrants.size();

      log.info(
          "Completed scheduled task: revoked {} ACCESS_GRANT records in {} ms",
          expiredGrants.size(), executionTime
      );

    } catch (Exception e) {
      log.error("Unexpected error in scheduled grant expiration task", e);
    }
  }

  /**
   * Revoke a single expired grant and log the operation.
   */
  private void revokeExpiredGrant(AccessGrant grant) {
    ZonedDateTime now = ZonedDateTime.now();

    // Mark grant as revoked with automatic system revocation reason
    grant.setRevoked(true);
    grant.setRevokedAt(now);
    grant.setRevokedByUser(null); // System revocation (no specific admin)
    grant.setRevokeReason("Automatic expiration");

    AccessGrant revokedGrant = grantRepository.save(grant);

    log.info(
        "Revoked expired grant: grantId={}, documentId={}, granteeUserId={}, expiresAt={}",
        grant.getId(), grant.getDocument().getId(),
        grant.getGranteeUser().getId(), grant.getExpiresAt()
    );

    // Log audit event for automatic revocation
    AccessEventLog event = AccessEventLog.builder()
        .user(grant.getGranteeUser())
        .document(grant.getDocument())
        .action(AccessAction.REVOKE)
        .result(AccessResult.SUCCESS)
        .reason("Automatic expiration at " + grant.getExpiresAt())
        .metadata("{\"revocation_type\":\"automatic\",\"grant_id\":\"" + grant.getId()
            + "\"}")
        .timestampUtc(now)
        .build();

    auditLogRepository.save(event);
  }

  /**
   * Get execution statistics for monitoring.
   */
  public GrantExpirationStats getStats() {
    return GrantExpirationStats.builder()
        .lastExecutionTimeMs(lastExecutionTime)
        .lastRevokedCount(lastRevokedCount)
        .enabled(expirationCheckEnabled)
        .intervalSeconds(expirationCheckIntervalSeconds)
        .build();
  }

  /**
   * DTO for expiration task statistics.
   */
  @lombok.Getter
  @lombok.Setter
  @lombok.AllArgsConstructor
  @lombok.Builder
  public static class GrantExpirationStats {
    private Long lastExecutionTimeMs;
    private Integer lastRevokedCount;
    private Boolean enabled;
    private Integer intervalSeconds;
  }
}