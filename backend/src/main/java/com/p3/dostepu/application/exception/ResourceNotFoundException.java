package com.p3.dostepu.application.exception;

/**
 * Exception thrown when a resource (document, user, grant) is not found.
 */
public class ResourceNotFoundException extends RuntimeException {
  public ResourceNotFoundException(String message) {
    super(message);
  }

  public ResourceNotFoundException(String message, Throwable cause) {
    super(message, cause);
  }
}