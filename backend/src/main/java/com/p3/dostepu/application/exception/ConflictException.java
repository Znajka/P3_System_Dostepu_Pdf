package com.p3.dostepu.application.exception;

/**
 * Exception thrown when a conflict occurs (e.g., duplicate active grant).
 */
public class ConflictException extends RuntimeException {
  public ConflictException(String message) {
    super(message);
  }

  public ConflictException(String message, Throwable cause) {
    super(message, cause);
  }
}