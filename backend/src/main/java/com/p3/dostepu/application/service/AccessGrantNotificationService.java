package com.p3.dostepu.application.service;

import java.time.ZonedDateTime;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.p3.dostepu.domain.entity.AccessGrant;
import com.p3.dostepu.domain.repository.AccessGrantRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Optional service for notifying users about expiring access grants.
 * Runs daily and sends notifications for grants expiring within 24 hours.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccessGrantNotificationService {

  private final AccessGrantRepository grantRepository;

  @Value("${app.scheduled.expiration-notification-enabled:false}")
  private Boolean notificationEnabled;

  @Value("${app.scheduled.expiration-notification-hours-before:24}")
  private Integer hoursBeforeExpiration;

  /**
   * Scheduled task: notify users about grants expiring soon.
   * Runs daily at 9 AM UTC by default.
   */
  @Scheduled(cron = "0 0 9 * * *", zone = "UTC")
  @Transactional(readOnly = true)
  public void notifyExpiringGrants() {
    try {
      if (!notificationEnabled) {
        log.debug("Grant expiration notifications are disabled");
        return;
      }

      ZonedDateTime now = ZonedDateTime.now();
      ZonedDateTime soon = now.plusHours(hoursBeforeExpiration);

      log.info(
          "Starting notification task: grants expiring within {} hours",
          hoursBeforeExpiration
      );

      List<AccessGrant> expiringGrants = grantRepository.findExpiringWithinDays(now, soon);

      if (expiringGrants.isEmpty()) {
        log.debug("No grants expiring soon");
        return;
      }

      log.info("Found {} grants expiring within {} hours",
          expiringGrants.size(), hoursBeforeExpiration);

      // Step: Send notifications (email, in-app, etc.)
      for (AccessGrant grant : expiringGrants) {
        try {
          sendExpirationNotification(grant);
        } catch (Exception e) {
          log.error(
              "Failed to send notification for grant: grantId={}, grantee={}",
              grant.getId(), grant.getGranteeUser().getId(), e
          );
        }
      }

      log.info("Completed notification task: notified {} users", expiringGrants.size());

    } catch (Exception e) {
      log.error("Unexpected error in grant expiration notification task", e);
    }
  }

  /**
   * Send expiration notification to user (placeholder).
   * TODO: Implement email, in-app messaging, or webhook integration.
   */
  private void sendExpirationNotification(AccessGrant grant) {
    log.info(
        "Sending expiration notification: granteeId={}, documentId={}, expiresAt={}",
        grant.getGranteeUser().getId(), grant.getDocument().getId(),
        grant.getExpiresAt()
    );

    // TODO: Implement notification delivery
    // - Email via SMTP
    // - In-app notification via WebSocket
    // - Webhook to external service
    // - SMS via Twilio
  }
}