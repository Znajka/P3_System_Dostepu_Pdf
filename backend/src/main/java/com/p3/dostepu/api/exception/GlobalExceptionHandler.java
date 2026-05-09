package com.p3.dostepu.api.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;
import com.p3.dostepu.api.response.ErrorResponse;
import com.p3.dostepu.application.exception.RateLimitExceededException;
import com.p3.dostepu.application.exception.ResourceNotFoundException;
import com.p3.dostepu.application.exception.UnauthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.server.ResponseStatusException;

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

  /** Multipart uploads over configured limit (align with app document max size). */
  @ExceptionHandler(MaxUploadSizeExceededException.class)
  public ResponseEntity<ErrorResponse> handleMaxUpload(
      MaxUploadSizeExceededException ex,
      HttpServletRequest request
  ) {
    log.warn("Upload too large: {}", ex.getMessage());
    return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
        .body(ErrorResponse.of(
            "FILE_TOO_LARGE",
            "Uploaded file exceeds the maximum allowed size (100 MB).",
            request.getHeader("X-Trace-ID")));
  }

  @ExceptionHandler(MultipartException.class)
  public ResponseEntity<ErrorResponse> handleMultipartParse(
      MultipartException ex,
      HttpServletRequest request
  ) {
    Throwable root = unwrap(ex);
    if (root.getClass().getSimpleName().equals("FileSizeLimitExceededException")
        || containsMessage(root, "maximum permitted size")
        || containsMessage(root, "SizeLimitExceededException")) {
      log.warn("Multipart size limit: {}", root.getMessage());
      return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
          .body(ErrorResponse.of(
              "FILE_TOO_LARGE",
              "Uploaded file exceeds the maximum allowed size (100 MB).",
              request.getHeader("X-Trace-ID")));
    }
    log.error("Multipart error: {}", ex.getMessage(), ex);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST)
        .body(ErrorResponse.of(
            "BAD_MULTIPART_REQUEST",
            "Could not parse upload request.",
            request.getHeader("X-Trace-ID")));
  }

  /**
   * Preserve status from {@link ResponseStatusException}; it subclasses
   * {@link RuntimeException} and would otherwise be turned into HTTP 500 here.
   */
  @ExceptionHandler(ResponseStatusException.class)
  public ResponseEntity<ErrorResponse> handleResponseStatusException(
      ResponseStatusException ex,
      HttpServletRequest request
  ) {
    HttpStatus resolved = HttpStatus.resolve(ex.getStatusCode().value());
    if (resolved == null) {
      resolved = HttpStatus.INTERNAL_SERVER_ERROR;
    }
    String detail = ex.getReason() != null ? ex.getReason()
        : resolved.getReasonPhrase();
    if (resolved.value() >= HttpStatus.BAD_REQUEST.value()
        && resolved.value() < HttpStatus.INTERNAL_SERVER_ERROR.value()) {
      log.warn("Request rejected ({}): {}", resolved.value(),
          truncate(detail, 256));
    } else {
      log.warn("Stream/upstream rejected ({}): {}", resolved.value(),
          truncate(detail, 256));
    }
    return ResponseEntity.status(ex.getStatusCode())
        .body(ErrorResponse.of(
            "HTTP_" + ex.getStatusCode().value(),
            detail,
            request.getHeader("X-Trace-ID")
        ));
  }

  private static String truncate(String s, int max) {
    if (s == null) {
      return "";
    }
    return s.length() > max ? s.substring(0, max) + "…" : s;
  }

  /**
   * Handle generic runtime exceptions (HTTP 500).
   */
  @ExceptionHandler(RuntimeException.class)
  public ResponseEntity<ErrorResponse> handleRuntimeException(
      RuntimeException ex,
      HttpServletRequest request
  ) {
    if (ex instanceof ResponseStatusException rse) {
      return handleResponseStatusException(rse, request);
    }
    if (multipartUploadTooLarge(ex)) {
      log.warn("Upload too large: {}", ex.getMessage());
      return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
          .body(ErrorResponse.of(
              "FILE_TOO_LARGE",
              "Uploaded file exceeds the maximum allowed size (100 MB).",
              request.getHeader("X-Trace-ID")));
    }

    log.error("Internal server error: {}", ex.getMessage(), ex);

    return ResponseEntity
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(ErrorResponse.of(
            "INTERNAL_SERVER_ERROR",
            "An internal error occurred",
            request.getHeader("X-Trace-ID")
        ));
  }

  private static Throwable unwrap(Throwable ex) {
    Throwable t = ex;
    while (t.getCause() != null && t.getCause() != t) {
      t = t.getCause();
    }
    return t;
  }

  private static boolean containsMessage(Throwable t, String sub) {
    for (Throwable c = t; c != null; c = c.getCause()) {
      String m = c.getMessage();
      if (m != null && m.contains(sub)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Tomcat parses multipart before some Spring wrappers; oversized file may arrive as {@link IllegalStateException}.
   */
  private static boolean multipartUploadTooLarge(RuntimeException ex) {
    return containsMessage(ex, "FileSizeLimitExceededException")
        || containsMessage(ex, "maximum permitted size")
        || containsMessage(ex, "MaxUploadSizeExceededException");
  }
}