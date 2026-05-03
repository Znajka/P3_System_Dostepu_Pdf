package com.p3.dostepu.infrastructure.security;

import java.time.ZonedDateTime;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.p3.dostepu.application.exception.RateLimitExceededException;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Rate Limiter Service (simplified, without Bucket4j).
 * Per CONTRIBUTING.md Rate Limiting & Lockout Policy:
 *   - Default: 5 failed attempts -> account lockout
 *   - Locks account on threshold exceeded
 *   - Unlock after lockout window expires
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RateLimiterService {

  private final UserRepository userRepository;

  @Value("${app.rate-limit.enabled:true}")
  private Boolean rateLimitEnabled;

  @Value("${app.rate-limit.failed-attempts:5}")
  private Integer maxFailedAttempts;

  @Value("${app.rate-limit.lockout-minutes:30}")
  private Integer lockoutMinutes;

  /**
   * Check if user can perform an access attempt.
   * Throws RateLimitExceededException if user locked.
   *
   * @param userId user UUID
   * @param endpoint operation identifier
   * @throws RateLimitExceededException if user is locked
   */
  public void checkRateLimit(UUID userId, String endpoint) {
    if (!rateLimitEnabled) {
      log.debug("Rate limiting disabled");
      return;
    }

    User user = userRepository.findById(userId)
        .orElseThrow(() -> new RuntimeException("User not found: " + userId));

    if (user.isLocked()) {
      ZonedDateTime lockUntil = user.getLockUntil();
      long retryAfterSeconds = java.time.temporal.ChronoUnit.SECONDS
          .between(ZonedDateTime.now(), lockUntil);

      log.warn(
          "User locked: userId={}, lockUntil={}, retryAfterSeconds={}",
          userId, lockUntil, retryAfterSeconds
      );

      throw new RateLimitExceededException(
          String.format(
              "Account locked due to repeated failed attempts. Try again in %d seconds.",
              retryAfterSeconds
          ),
          retryAfterSeconds,
          lockUntil
      );
    }

    log.debug("Rate limit check passed: userId={}, endpoint={}", userId, endpoint);
  }

  /**
   * Record a failed access attempt.
   * If threshold exceeded, lock user account.
   *
   * @param userId user UUID
   * @param endpoint operation identifier
   */
  public void recordFailedAttempt(UUID userId, String endpoint) {
    if (!rateLimitEnabled) {
      return;
    }

    User user = userRepository.findById(userId)
        .orElseThrow(() -> new RuntimeException("User not found: " + userId));

    int currentAttempts = (user.getFailedAttempts() != null ? user.getFailedAttempts() : 0) + 1;
    user.setFailedAttempts(currentAttempts);

    if (currentAttempts >= maxFailedAttempts) {
      user.lock(lockoutMinutes);
      log.warn(
          "User locked after {} failed attempts: userId={}, lockUntil={}",
          currentAttempts, userId, user.getLockUntil()
      );
    }

    userRepository.save(user);
    log.info(
        "Failed attempt recorded: userId={}, endpoint={}, totalAttempts={}",
        userId, endpoint, currentAttempts
    );
  }

  /**
   * Reset failed attempts counter on successful access.
   *
   * @param userId user UUID
   */
  public void resetFailedAttempts(UUID userId) {
    if (!rateLimitEnabled) {
      return;
    }

    User user = userRepository.findById(userId)
        .orElseThrow(() -> new RuntimeException("User not found: " + userId));

    if (user.getFailedAttempts() > 0 || user.isLocked()) {
      user.unlock();
      userRepository.save(user);
      log.info("Failed attempts reset: userId={}", userId);
    }
  }

  /**
   * Manually unlock a user (admin operation).
   *
   * @param userId user UUID
   */
  public void unlockUser(UUID userId) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new RuntimeException("User not found: " + userId));

    user.unlock();
    userRepository.save(user);
    log.info("User unlocked (admin): userId={}", userId);
  }

  /**
   * Get remaining time (seconds) until user is unlocked.
   * Returns 0 if not locked.
   *
   * @param userId user UUID
   * @return seconds until unlock (0 if not locked)
   */
  public long getSecondsUntilUnlock(UUID userId) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new RuntimeException("User not found: " + userId));

    if (!user.isLocked()) {
      return 0;
    }

    return java.time.temporal.ChronoUnit.SECONDS
        .between(ZonedDateTime.now(), user.getLockUntil());
  }

  /**
   * Get rate limit statistics.
   */
  public RateLimitStats getStats(UUID userId) {
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new RuntimeException("User not found: " + userId));

    return RateLimitStats.builder()
        .userId(userId)
        .failedAttempts(user.getFailedAttempts())
        .isLocked(user.isLocked())
        .lockUntil(user.getLockUntil())
        .secondsUntilUnlock(user.isLocked()
            ? java.time.temporal.ChronoUnit.SECONDS
                .between(ZonedDateTime.now(), user.getLockUntil())
            : 0)
        .maxAttempts(maxFailedAttempts)
        .lockoutMinutes(lockoutMinutes)
        .build();
  }

  /**
   * DTO for rate limit statistics.
   */
  @lombok.Getter
  @lombok.Setter
  @lombok.AllArgsConstructor
  @lombok.Builder
  public static class RateLimitStats {
    private UUID userId;
    private Integer failedAttempts;
    private Boolean isLocked;
    private ZonedDateTime lockUntil;
    private Long secondsUntilUnlock;
    private Integer maxAttempts;
    private Integer lockoutMinutes;
  }
}