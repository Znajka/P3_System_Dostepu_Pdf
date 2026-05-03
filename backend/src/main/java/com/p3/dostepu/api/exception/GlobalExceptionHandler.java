package com.p3.dostepu.api.exception;

import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.p3.dostepu.api.response.ErrorResponse;
import com.p3.dostepu.application.exception.RateLimitExceededException;
import com.p3.dostepu.application.exception.ResourceNotFoundException;
import com.p3.dostepu.application.exception.UnauthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

/**
 * Global exception handler for REST API.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

  /**
   * Handle rate limit exceeded (HTTP 429 Too Many Requests).
   */
  @ExceptionHandler(RateLimitExceededException.class)
  public ResponseEntity<ErrorResponse> handleRateLimitExceeded(
      RateLimitExceededException ex,
      HttpServletRequest request
  ) {
    log.warn("Rate limit exceeded: {}", ex.getMessage());

    ErrorResponse errorResponse = ErrorResponse.of(
        "RATE_LIMIT_EXCEEDED",
        ex.getMessage(),
        request.getHeader("X-Trace-ID")
    );

    ResponseEntity<ErrorResponse> response = ResponseEntity
        .status(HttpStatus.TOO_MANY_REQUESTS)
        .body(errorResponse);

    // Add Retry-After header (HTTP standard)
    return ResponseEntity
        .status(HttpStatus.TOO_MANY_REQUESTS)
        .header("Retry-After", String.valueOf(ex.getRetryAfterSeconds()))
        .header("X-RateLimit-Reset", ex.getLockUntil().toString())
        .body(errorResponse);
  }

  /**
   * Handle resource not found (HTTP 404).
   */
  @ExceptionHandler(ResourceNotFoundException.class)
  public ResponseEntity<ErrorResponse> handleResourceNotFound(
      ResourceNotFoundException ex,
      HttpServletRequest request
  ) {
    log.warn("Resource not found: {}", ex.getMessage());

    return ResponseEntity
        .status(HttpStatus.NOT_FOUND)
        .body(ErrorResponse.of(
            "NOT_FOUND",
            ex.getMessage(),
            request.getHeader("X-Trace-ID")
        ));
  }

  /**
   * Handle unauthorized (HTTP 401).
   */
  @ExceptionHandler(UnauthorizedException.class)
  public ResponseEntity<ErrorResponse> handleUnauthorized(
      UnauthorizedException ex,
      HttpServletRequest request
  ) {
    log.warn("Unauthorized: {}", ex.getMessage());

    return ResponseEntity
        .status(HttpStatus.FORBIDDEN)
        .body(ErrorResponse.of(
            "FORBIDDEN",
            ex.getMessage(),
            request.getHeader("X-Trace-ID")
        ));
  }

  /**
   * Handle generic runtime exceptions (HTTP 500).
   */
  @ExceptionHandler(RuntimeException.class)
  public ResponseEntity<ErrorResponse> handleRuntimeException(
      RuntimeException ex,
      HttpServletRequest request
  ) {
    log.error("Internal server error: {}", ex.getMessage(), ex);

    return ResponseEntity
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(ErrorResponse.of(
            "INTERNAL_SERVER_ERROR",
            "An internal error occurred",
            request.getHeader("X-Trace-ID")
        ));
  }
}