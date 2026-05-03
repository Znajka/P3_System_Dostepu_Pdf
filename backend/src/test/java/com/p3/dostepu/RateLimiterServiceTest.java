package com.p3.dostepu;

import static org.junit.jupiter.api.Assertions.*;

import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import com.p3.dostepu.application.exception.RateLimitExceededException;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.entity.UserRole;
import com.p3.dostepu.domain.repository.UserRepository;
import com.p3.dostepu.infrastructure.security.RateLimiterService;

@SpringBootTest
class RateLimiterServiceTest {

  @Autowired
  private RateLimiterService rateLimiterService;

  @Autowired
  private UserRepository userRepository;

  private User testUser;

  @BeforeEach
  void setUp() {
    testUser = User.builder()
        .username("testuser")
        .email("test@example.com")
        .passwordHash("hashed-password")
        .roles(java.util.Set.of(UserRole.USER))
        .failedAttempts(0)
        .active(true)
        .build();

    testUser = userRepository.save(testUser);
  }

  @Test
  void testRateLimitAllowsAttemptsWithinLimit() {
    // Should allow 5 attempts within window
    for (int i = 0; i < 5; i++) {
      assertDoesNotThrow(() ->
          rateLimiterService.checkRateLimit(testUser.getId(), "open-ticket")
      );
    }
  }

  @Test
  void testRateLimitExceedsAfterMaxAttempts() {
    // Exhaust bucket
    for (int i = 0; i < 5; i++) {
      rateLimiterService.checkRateLimit(testUser.getId(), "open-ticket");
    }

    // 6th attempt should fail
    assertThrows(RateLimitExceededException.class, () ->
        rateLimiterService.checkRateLimit(testUser.getId(), "open-ticket")
    );
  }

  @Test
  void testRecordFailedAttemptLocksUserAfterThreshold() {
    UUID userId = testUser.getId();

    // Record 5 failed attempts
    for (int i = 0; i < 5; i++) {
      rateLimiterService.recordFailedAttempt(userId, "open-ticket");
    }

    // User should be locked
    User lockedUser = userRepository.findById(userId).orElseThrow();
    assertTrue(lockedUser.isLocked());
  }

  @Test
  void testLockedUserCannotAccess() {
    UUID userId = testUser.getId();

    // Lock user
    for (int i = 0; i < 5; i++) {
      rateLimiterService.recordFailedAttempt(userId, "open-ticket");
    }

    // Attempt to access should fail
    assertThrows(RateLimitExceededException.class, () ->
        rateLimiterService.checkRateLimit(userId, "open-ticket")
    );
  }

  @Test
  void testUnlockUser() {
    UUID userId = testUser.getId();

    // Lock user
    for (int i = 0; i < 5; i++) {
      rateLimiterService.recordFailedAttempt(userId, "open-ticket");
    }

    // Unlock
    rateLimiterService.unlockUser(userId);

    // Should be able to access now
    assertDoesNotThrow(() ->
        rateLimiterService.checkRateLimit(userId, "open-ticket")
    );
  }

  @Test
  void testResetFailedAttempts() {
    UUID userId = testUser.getId();

    // Record some failed attempts
    for (int i = 0; i < 3; i++) {
      rateLimiterService.recordFailedAttempt(userId, "open-ticket");
    }

    // Reset
    rateLimiterService.resetFailedAttempts(userId);

    // User should have 0 failed attempts
    User user = userRepository.findById(userId).orElseThrow();
    assertEquals(0, user.getFailedAttempts());
  }
}