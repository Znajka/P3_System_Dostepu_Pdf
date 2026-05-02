package com.p3.dostepu.application.exception;

/**
 * Exception thrown when user is not authorized for an operation.
 */
public class UnauthorizedException extends RuntimeException {
  public UnauthorizedException(String message) {
    super(message);
  }

  public UnauthorizedException(String message, Throwable cause) {
    super(message, cause);
  }
}