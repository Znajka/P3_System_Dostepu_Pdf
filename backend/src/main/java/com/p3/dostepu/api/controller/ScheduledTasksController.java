package com.p3.dostepu.api.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.p3.dostepu.application.service.AccessGrantExpirationService;
import com.p3.dostepu.application.service.AccessGrantExpirationService.GrantExpirationStats;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Admin endpoints for monitoring and managing scheduled tasks.
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/scheduled-tasks")
@RequiredArgsConstructor
public class ScheduledTasksController {

  private final AccessGrantExpirationService expirationService;

  /**
   * GET /api/admin/scheduled-tasks/grant-expiration/stats
   * Get statistics for grant expiration scheduled task.
   */
  @GetMapping("/grant-expiration/stats")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<GrantExpirationStats> getGrantExpirationStats() {
    log.info("Fetching grant expiration task stats");
    GrantExpirationStats stats = expirationService.getStats();
    return ResponseEntity.ok(stats);
  }

  /**
   * POST /api/admin/scheduled-tasks/grant-expiration/trigger
   * Manually trigger grant expiration task (for testing/admin).
   */
  @PostMapping("/grant-expiration/trigger")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<Void> triggerGrantExpiration() {
    log.info("Admin triggered grant expiration task");
    expirationService.revokeExpiredGrants();
    return ResponseEntity.noContent().build();
  }
}