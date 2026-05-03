package com.p3.dostepu.api.controller;

import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.p3.dostepu.infrastructure.security.RateLimiterService;
import com.p3.dostepu.infrastructure.security.RateLimiterService.RateLimitStats;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Rate limit admin endpoints (ADMIN role required).
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/rate-limits")
@RequiredArgsConstructor
public class RateLimitController {

  private final RateLimiterService rateLimiterService;

  /**
   * GET /api/admin/rate-limits/{userId} - Get rate limit stats for user.
   */
  @GetMapping("/{userId}")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<RateLimitStats> getRateLimitStats(
      @PathVariable UUID userId
  ) {
    log.info("Getting rate limit stats: userId={}", userId);
    RateLimitStats stats = rateLimiterService.getStats(userId);
    return ResponseEntity.ok(stats);
  }

  /**
   * DELETE /api/admin/rate-limits/{userId}/unlock - Unlock user.
   */
  @DeleteMapping("/{userId}/unlock")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<Void> unlockUser(
      @PathVariable UUID userId
  ) {
    log.info("Unlocking user: userId={}", userId);
    rateLimiterService.unlockUser(userId);
    return ResponseEntity.noContent().build();
  }
}