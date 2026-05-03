package com.p3.dostepu.infrastructure.security;

import java.time.ZonedDateTime;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;
import com.github.bucket4j.Bandwidth;
import com.github.bucket4j.Bucket;
import com.github.bucket4j.Bucket4j;
import com.github.bucket4j.Refill;
import com.p3.dostepu.application.exception.RateLimitExceededException;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Rate Limiter Service using Bucket4j.
 * Per CONTRIBUTING.md Rate Limiting & Lockout Policy:
 *   - Default: 5 failed attempts in 15 minutes -> 30-minute lockout
 *   - Validates per-user and per-endpoint
 *   - Locks account on threshold exceeded
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RateLimiterService {

  private final CacheManager cacheManager;
  private final UserRepository userRepository;

  @Value("${app.rate-limit.enabled:true}")
  private Boolean rateLimitEnabled;

  @Value("${app.rate-limit.failed-attempts:5}")
  private Integer maxFailedAttempts;

  @Value("${app.rate-limit.window-minutes:15}")
  private Integer windowMinutes;

  @Value("${app.rate-limit.lockout-minutes:30}")
  private Integer lockoutMinutes;

  /**
   * Check if user can perform an access attempt (rate-limited operation).
   * Throws RateLimitExceededException if limit exceeded or user locked.
   *
   * @param userId user UUID
   * @param endpoint operation identifier (e.g., "open-ticket", "grant-access")
   * @throws RateLimitExceededException if rate limit exceeded or user locked
   */
  public void checkRateLimit(UUID userId, String endpoint) {
    if (!rateLimitEnabled) {
      log.debug("Rate limiting disabled");
      return;
    }

    // Step 1: Check if user is locked
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
              "Account locked due to repeated failed attempts. "
                  + "Try again in %d seconds.",
              retryAfterSeconds
          ),
          retryAfterSeconds,
          lockUntil
      );
    }

    // Step 2: Check bucket for this user + endpoint
    String bucketKey = generateBucketKey(userId, endpoint);
    Bucket bucket = resolveBucket(bucketKey);

    if (!bucket.tryConsume(1)) {
      long tokensLeft = bucket.estimateAbilityToConsume(1).getRoundedSecondsToWait();

      log.warn(
          "Rate limit exceeded: userId={}, endpoint={}, tokensLeft={}, "
              + "retryAfterSeconds={}",
          userId, endpoint, tokensLeft, tokensLeft
      );

      throw new RateLimitExceededException(
          String.format(
              "Rate limit exceeded. Please try again in %d seconds.",
              tokensLeft
          ),
          tokensLeft,
          ZonedDateTime.now().plusSeconds(lockoutMinutes * 60)
      );
    }

    log.debug(
        "Rate limit check passed: userId={}, endpoint={}, tokens={}",
        userId, endpoint, bucket.estimateAbilityToConsume(1).getAsLong()
    );
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

    // Step 1: Increment failed attempts in user entity
    User user = userRepository.findById(userId)
        .orElseThrow(() -> new RuntimeException("User not found: " + userId));

    user.setFailedAttempts((user.getFailedAttempts() != null ? user.getFailedAttempts() : 0)
        + 1);

    // Step 2: Check if threshold exceeded
    if (user.getFailedAttempts() >= maxFailedAttempts) {
      user.lock(lockoutMinutes);
      log.warn(
          "User locked after {} failed attempts: userId={}, lockUntil={}",
          user.getFailedAttempts(), userId, user.getLockUntil()
      );
    }

    userRepository.save(user);
    log.info(
        "Failed attempt recorded: userId={}, endpoint={}, totalAttempts={}",
        userId, endpoint, user.getFailedAttempts()
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
      log.info(
          "Failed attempts reset: userId={}, previousAttempts={}",
          userId, user.getFailedAttempts()
      );
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
   * Resolve or create bucket for user + endpoint.
   * Uses Bucket4j with token bucket algorithm.
   */
  private Bucket resolveBucket(String bucketKey) {
    org.springframework.cache.Cache cache = cacheManager.getCache("rate_limit_buckets");
    if (cache == null) {
      throw new RuntimeException("Cache not configured for rate limiting");
    }

    // Try to get existing bucket from cache
    Bucket bucket = cache.get(bucketKey, Bucket.class);

    if (bucket == null) {
      // Create new bucket
      Bandwidth limit = Bandwidth.classic(
          maxFailedAttempts,
          Refill.intervally(
              maxFailedAttempts,
              java.time.Duration.ofMinutes(windowMinutes)
          )
      );

      bucket = Bucket4j.builder()
          .addLimit(limit)
          .build();

      cache.put(bucketKey, bucket);
      log.debug("Created rate limit bucket: {}", bucketKey);
    }

    return bucket;
  }

  /**
   * Generate unique bucket key for user + endpoint.
   */
  private String generateBucketKey(UUID userId, String endpoint) {
    return String.format("rate_limit:%s:%s", userId, endpoint);
  }

  /**
   * Get rate limit statistics (for monitoring/debugging).
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
        .windowMinutes(windowMinutes)
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
    private Integer windowMinutes;
    private Integer lockoutMinutes;
  }
}