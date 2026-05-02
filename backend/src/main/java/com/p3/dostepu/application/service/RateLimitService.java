package com.p3.dostepu.application.service;

import java.time.ZonedDateTime;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.p3.dostepu.domain.entity.RateLimitState;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.repository.RateLimitStateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * RateLimitService: manages per-user rate-limiting and account lockout.
 * Policy: N failed attempts within window -> temporary lockout for M minutes.
 * Per CONTRIBUTING.md: default 5 failures in 15 minutes -> 30-minute lockout.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RateLimitService {

  private final RateLimitStateRepository rateLimitRepository;

  @Value("${app.rate-limit.enabled:true}")
  private Boolean rateLimitEnabled;

  @Value("${app.rate-limit.failed-attempts:5}")
  private Integer maxFailedAttempts;

  @Value("${app.rate-limit.window-minutes:15}")
  private Integer windowMinutes;

  @Value("${app.rate-limit.lockout-minutes:30}")
  private Integer lockoutMinutes;

  /**
   * Check if user is currently locked due to rate-limit violation.
   *
   * @param userId user UUID
   * @return true if user is locked, false otherwise
   */
  @Transactional(readOnly = true)
  public boolean isUserLocked(UUID userId) {
    if (!rateLimitEnabled) {
      return false;
    }

    RateLimitState state = rateLimitRepository.findByUserId(userId).orElse(null);
    if (state == null) {
      return false;
    }

    ZonedDateTime now = ZonedDateTime.now();
    if (state.getLockUntil() != null && state.getLockUntil().isAfter(now)) {
      log.warn("User is locked: {}", userId);
      return true;
    }

    return false;
  }

  /**
   * Record failed access attempt and check if user should be locked.
   *
   * @param userId user UUID
   * @return true if user is now locked; false otherwise
   */
  @Transactional
  public boolean recordFailedAttempt(UUID userId) {
    if (!rateLimitEnabled) {
      return false;
    }

    RateLimitState state = rateLimitRepository.findByUserId(userId)
        .orElse(RateLimitState.builder().user(new User() {
          {
            setId(userId);
          }
        }).build());

    state.incrementFailedAttempts();
    state.setLastFailedAttempt(ZonedDateTime.now());

    // Check if should lock
    if (state.getFailedAttempts() >= maxFailedAttempts) {
      state.setLockUntil(ZonedDateTime.now().plusMinutes(lockoutMinutes));
      log.warn("User locked after {} failed attempts: {}", maxFailedAttempts, userId);
      rateLimitRepository.save(state);
      return true;
    }

    rateLimitRepository.save(state);
    return false;
  }

  /**
   * Reset failed attempts and unlock user on successful access.
   *
   * @param userId user UUID
   */
  @Transactional
  public void resetFailedAttempts(UUID userId) {
    if (!rateLimitEnabled) {
      return;
    }

    RateLimitState state = rateLimitRepository.findByUserId(userId).orElse(null);
    if (state != null) {
      state.resetAttempts();
      rateLimitRepository.save(state);
      log.info("Reset failed attempts for user: {}", userId);
    }
  }

  /**
   * Get remaining lockout time in seconds. Returns 0 if not locked.
   */
  public long getRemainingLockoutSeconds(UUID userId) {
    RateLimitState state = rateLimitRepository.findByUserId(userId).orElse(null);
    if (state == null || state.getLockUntil() == null) {
      return 0;
    }

    ZonedDateTime now = ZonedDateTime.now();
    if (state.getLockUntil().isAfter(now)) {
      return java.time.temporal.ChronoUnit.SECONDS.between(now,
          state.getLockUntil());
    }

    return 0;
  }
}