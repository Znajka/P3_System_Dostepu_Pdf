package com.p3.dostepu.application.exception;

import java.time.ZonedDateTime;

/**
 * Exception thrown when rate limit is exceeded or user is locked.
 */
public class RateLimitExceededException extends RuntimeException {
  private final long retryAfterSeconds;
  private final ZonedDateTime lockUntil;

  public RateLimitExceededException(
      String message,
      long retryAfterSeconds,
      ZonedDateTime lockUntil
  ) {
    super(message);
    this.retryAfterSeconds = retryAfterSeconds;
    this.lockUntil = lockUntil;
  }

  public long getRetryAfterSeconds() {
    return retryAfterSeconds;
  }

  public ZonedDateTime getLockUntil() {
    return lockUntil;
  }
}