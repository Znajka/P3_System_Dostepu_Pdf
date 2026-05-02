package com.p3.dostepu.api.controller;

import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.p3.dostepu.api.dto.AccessGrantRequest;
import com.p3.dostepu.api.dto.AccessGrantResponse;
import com.p3.dostepu.api.response.ErrorResponse;
import com.p3.dostepu.application.exception.ConflictException;
import com.p3.dostepu.application.exception.ResourceNotFoundException;
import com.p3.dostepu.application.exception.UnauthorizedException;
import com.p3.dostepu.application.service.AccessGrantService;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.repository.UserRepository;
import com.p3.dostepu.security.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Access Grant API controller: handles grant and revoke operations.
 * Endpoints:
 *   POST /api/documents/{id}/grant - grant access
 *   POST /api/documents/{id}/revoke - revoke access
 * Only OWNER or ADMIN can grant/revoke.
 */
@Slf4j
@RestController
@RequestMapping("/api/documents")
@RequiredArgsConstructor
public class AccessGrantController {

  private final AccessGrantService grantService;
  private final UserRepository userRepository;

  /**
   * POST /api/documents/{id}/grant - Grant document access to a user.
   * Request body: granteeUserId, expiresAt (ISO 8601 UTC), optional note.
   * Returns 200 OK with grant metadata.
   *
   * @param documentId document UUID (path parameter)
   * @param request grant request DTO
   * @param httpRequest HTTP request (for client IP extraction)
   * @return AccessGrantResponse with grant ID and metadata
   */
  @PostMapping("/{id}/grant")
  @PreAuthorize("hasAnyRole('ADMIN', 'OWNER')")
  public ResponseEntity<?> grantAccess(
      @PathVariable(value = "id") UUID documentId,
      @Valid @RequestBody AccessGrantRequest request,
      HttpServletRequest httpRequest) {

    try {
      // Extract authenticated user
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
      UUID userId = userDetails.getUserId();

      User grantedBy = userRepository.findById(userId)
          .orElseThrow(() -> new RuntimeException("Authenticated user not found"));

      // Get client IP for audit
      String clientIp = getClientIp(httpRequest);

      log.info("Grant access request: document={}, grantee={}, grantedBy={}", documentId,
          request.getGranteeUserId(), userId);

      // Process grant
      AccessGrantResponse response = grantService.grantAccess(documentId, request,
          grantedBy, clientIp);

      return ResponseEntity.ok(response);

    } catch (ResourceNotFoundException e) {
      log.warn("Resource not found: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.NOT_FOUND)
          .body(ErrorResponse.of("NOT_FOUND", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));

    } catch (UnauthorizedException e) {
      log.warn("Unauthorized: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.FORBIDDEN)
          .body(ErrorResponse.of("FORBIDDEN", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));

    } catch (ConflictException e) {
      log.warn("Conflict: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.CONFLICT)
          .body(ErrorResponse.of("CONFLICT", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));

    } catch (IllegalArgumentException e) {
      log.warn("Invalid request: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(ErrorResponse.of("BAD_REQUEST", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));

    } catch (Exception e) {
      log.error("Grant access failed: {}", e.getMessage(), e);
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(ErrorResponse.of("GRANT_FAILED", "Failed to grant access",
              httpRequest.getHeader("X-Trace-ID")));
    }
  }

  /**
   * POST /api/documents/{id}/revoke - Revoke document access from a user.
   * Request body: granteeUserId (or grantId), optional reason.
   * Returns 200 OK with revoke metadata.
   *
   * @param documentId document UUID (path parameter)
   * @param request revoke request (granteeUserId, reason)
   * @param httpRequest HTTP request (for client IP extraction)
   * @return AccessGrantResponse with revoke metadata
   */
  @PostMapping("/{id}/revoke")
  @PreAuthorize("hasAnyRole('ADMIN', 'OWNER')")
  public ResponseEntity<?> revokeAccess(
      @PathVariable(value = "id") UUID documentId,
      @Valid @RequestBody AccessRevokeRequest request,
      HttpServletRequest httpRequest) {

    try {
      // Extract authenticated user
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
      UUID userId = userDetails.getUserId();

      User revokedBy = userRepository.findById(userId)
          .orElseThrow(() -> new RuntimeException("Authenticated user not found"));

      // Get client IP for audit
      String clientIp = getClientIp(httpRequest);

      UUID granteeUserId = UUID.fromString(request.getGranteeUserId());

      log.info("Revoke access request: document={}, grantee={}, revokedBy={}", documentId,
          request.getGranteeUserId(), userId);

      // Process revoke
      AccessGrantResponse response = grantService.revokeAccess(documentId, granteeUserId,
          revokedBy, request.getReason(), clientIp);

      return ResponseEntity.ok(response);

    } catch (ResourceNotFoundException e) {
      log.warn("Resource not found: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.NOT_FOUND)
          .body(ErrorResponse.of("NOT_FOUND", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));

    } catch (UnauthorizedException e) {
      log.warn("Unauthorized: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.FORBIDDEN)
          .body(ErrorResponse.of("FORBIDDEN", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));

    } catch (IllegalArgumentException e) {
      log.warn("Invalid request: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(ErrorResponse.of("BAD_REQUEST", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));

    } catch (Exception e) {
      log.error("Revoke access failed: {}", e.getMessage(), e);
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(ErrorResponse.of("REVOKE_FAILED", "Failed to revoke access",
              httpRequest.getHeader("X-Trace-ID")));
    }
  }

  /**
   * Extract client IP from HTTP request (handle proxies).
   */
  private String getClientIp(HttpServletRequest request) {
    String xForwardedFor = request.getHeader("X-Forwarded-For");
    if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
      return xForwardedFor.split(",")[0].trim();
    }
    String xRealIp = request.getHeader("X-Real-IP");
    if (xRealIp != null && !xRealIp.isEmpty()) {
      return xRealIp;
    }
    return request.getRemoteAddr();
  }
}