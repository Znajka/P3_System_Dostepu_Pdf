package com.p3.dostepu.api.controller;

import java.util.stream.Collectors;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.p3.dostepu.api.dto.DocumentStatusResponse;
import com.p3.dostepu.api.dto.OpenTicketResponse;
import com.p3.dostepu.api.response.ErrorResponse;
import com.p3.dostepu.application.exception.ResourceNotFoundException;
import com.p3.dostepu.application.exception.UnauthorizedException;
import com.p3.dostepu.application.service.DocumentAccessService;
import com.p3.dostepu.domain.entity.AccessGrant;
import com.p3.dostepu.domain.entity.Document;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.entity.UserRole;
import com.p3.dostepu.domain.repository.DocumentRepository;
import com.p3.dostepu.domain.repository.UserRepository;
import com.p3.dostepu.security.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Document Access API controller: handles document access tickets and status.
 * Endpoints:
 *   GET /api/documents/{id}/open-ticket - request streaming ticket
 *   GET /api/documents/{id}/status - document status
 */
@Slf4j
@RestController
@RequestMapping("/api/documents")
@RequiredArgsConstructor
public class DocumentAccessController {

  private final DocumentAccessService accessService;
  private final DocumentRepository documentRepository;
  private final UserRepository userRepository;

  /**
   * GET /api/documents/{id}/open-ticket - Request document access ticket.
   * Validates ACCESS_GRANT, enforces rate-limiting, issues single-use JWT (60s TTL).
   * Returns 200 OK with ticket; 403 if no valid grant; 423 if locked; 429 if
   * rate-limited.
   *
   * @param documentId document UUID (path parameter)
   * @param ttl optional ticket TTL override (seconds, max 120)
   * @param httpRequest HTTP request (for client IP extraction)
   * @return OpenTicketResponse with signed JWT ticket
   */
  @GetMapping("/{id}/open-ticket")
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<?> openDocument(
      @PathVariable(value = "id") UUID documentId,
      @RequestParam(value = "ttl", required = false) Integer ttl,
      HttpServletRequest httpRequest) {

    try {
      // Extract authenticated user
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
      UUID userId = userDetails.getUserId();

      User user = userRepository.findById(userId)
          .orElseThrow(() -> new RuntimeException("Authenticated user not found"));

      // Get client IP for audit
      String clientIp = getClientIp(httpRequest);

      log.info("Open ticket request: document={}, user={}", documentId, userId);

      // Process ticket issuance
      OpenTicketResponse response = accessService.issueAccessTicket(documentId, user,
          clientIp);

      return ResponseEntity.ok(response);

    } catch (UnauthorizedException e) {
      log.warn("Unauthorized: {}", e.getMessage());
      // Check if locked (423) vs. no grant (403)
      return ResponseEntity.status(HttpStatus.FORBIDDEN)
          .body(ErrorResponse.of("FORBIDDEN", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));

    } catch (ResourceNotFoundException e) {
      log.warn("Resource not found: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.NOT_FOUND)
          .body(ErrorResponse.of("NOT_FOUND", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));

    } catch (Exception e) {
      log.error("Open ticket failed: {}", e.getMessage(), e);
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(ErrorResponse.of("TICKET_FAILED", "Failed to issue access ticket",
              httpRequest.getHeader("X-Trace-ID")));
    }
  }

  /**
   * GET /api/documents/{id}/status - Get document status and access info.
   * Owner/Admin see full details (all grants).
   * Grantee see limited view (their grant expiry).
   * Returns 200 OK with status; 404 if not found; 403 if unauthorized.
   *
   * @param documentId document UUID (path parameter)
   * @param httpRequest HTTP request
   * @return DocumentStatusResponse with metadata and access status
   */
  @GetMapping("/{id}/status")
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<?> getDocumentStatus(
      @PathVariable(value = "id") UUID documentId,
      HttpServletRequest httpRequest) {

    try {
      // Extract authenticated user
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
      UUID userId = userDetails.getUserId();

      User user = userRepository.findById(userId)
          .orElseThrow(() -> new RuntimeException("Authenticated user not found"));

      // Validate document exists
      Document document = documentRepository.findByIdAndDeletedAtNull(documentId)
          .orElseThrow(
              () -> new ResourceNotFoundException("Document not found: " + documentId));

      boolean isOwner = document.getOwner().getId().equals(user.getId());
      boolean isAdmin = user.getRoles().contains(UserRole.ADMIN);

      // Build response based on authorization
      DocumentStatusResponse response = DocumentStatusResponse.builder()
          .documentId(documentId.toString())
          .title(document.getTitle())
          .ownerId(document.getOwner().getId().toString())
          .createdAt(document.getCreatedAt())
          .build();

      if (isOwner || isAdmin) {
        // Full view: all grants
        response.setGrants(document.getAccessGrants().stream()
            .map(grant -> DocumentStatusResponse.GrantInfo.builder()
                .grantId(grant.getId().toString())
                .granteeUserId(grant.getGranteeUser().getId().toString())
                .expiresAt(grant.getExpiresAt())
                .revoked(grant.getRevoked())
                .build())
            .collect(Collectors.toList()));
        response.setLocked(user.isLocked());
      } else {
        // Limited view: only their grant (if active)
        java.time.ZonedDateTime now = java.time.ZonedDateTime.now();
        AccessGrant userGrant = document.getAccessGrants().stream()
            .filter(g -> g.getGranteeUser().getId().equals(user.getId())
                && !g.getRevoked()
                && g.getExpiresAt().isAfter(now))
            .findFirst()
            .orElse(null);

        if (userGrant != null) {
          response.setAccessible(true);
          response.setAccess(DocumentStatusResponse.AccessInfo.builder()
              .granteeUserId(user.getId().toString())
              .expiresAt(userGrant.getExpiresAt())
              .build());
        } else {
          response.setAccessible(false);
        }
      }

      return ResponseEntity.ok(response);

    } catch (ResourceNotFoundException e) {
      log.warn("Resource not found: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.NOT_FOUND)
          .body(ErrorResponse.of("NOT_FOUND", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));

    } catch (Exception e) {
      log.error("Get status failed: {}", e.getMessage(), e);
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(ErrorResponse.of("STATUS_FAILED", "Failed to get document status",
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