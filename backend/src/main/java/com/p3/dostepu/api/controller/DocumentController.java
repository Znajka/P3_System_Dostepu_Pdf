package com.p3.dostepu.api.controller;

import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import com.p3.dostepu.api.dto.DocumentUploadRequest;
import com.p3.dostepu.api.dto.DocumentUploadResponse;
import com.p3.dostepu.api.response.ErrorResponse;
import com.p3.dostepu.application.service.DocumentService;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.repository.UserRepository;
import com.p3.dostepu.security.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Document API controller: handles document upload and metadata operations.
 * Endpoints:
 *   POST /api/documents - upload PDF
 *   POST /api/documents/{id}/grant - grant access
 *   POST /api/documents/{id}/revoke - revoke access
 *   GET /api/documents/{id}/open-ticket - request streaming ticket
 *   GET /api/documents/{id}/status - document status
 */
@Slf4j
@RestController
@RequestMapping("/api/documents")
@RequiredArgsConstructor
public class DocumentController {

  private final DocumentService documentService;
  private final UserRepository userRepository;

  /**
   * POST /api/documents - Upload PDF document.
   * Multipart request: file (PDF) + metadata (JSON).
   * Returns 201 Created with document ID.
   *
   * @param title document title (required)
   * @param description document description (optional)
   * @param tags document tags (optional)
   * @param file PDF file (required, multipart)
   * @return DocumentUploadResponse with document ID and metadata
   */
  @PostMapping(consumes = "multipart/form-data")
  @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
  public ResponseEntity<?> uploadDocument(
      @RequestParam(value = "title") String title,
      @RequestParam(value = "description", required = false) String description,
      @RequestParam(value = "tags", required = false) String[] tags,
      @RequestParam(value = "file") MultipartFile file,
      HttpServletRequest httpRequest) {

    try {
      // Extract authenticated user
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
      UUID userId = userDetails.getUserId();

      User owner = userRepository.findById(userId)
          .orElseThrow(() -> new RuntimeException("User not found"));

      // Build upload request
      DocumentUploadRequest request = DocumentUploadRequest.builder()
          .title(title)
          .description(description)
          .tags(tags)
          .visibleTo("private")
          .build();

      // Get client IP for audit
      String clientIp = getClientIp(httpRequest);

      log.info("Document upload initiated by user: {} from IP: {}", userId, clientIp);

      // Process upload
      DocumentUploadResponse response = documentService.uploadDocument(request, file,
          owner, clientIp);

      return ResponseEntity.status(HttpStatus.CREATED).body(response);

    } catch (IllegalArgumentException e) {
      log.warn("Invalid upload request: {}", e.getMessage());
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(ErrorResponse.of("BAD_REQUEST", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));

    } catch (RuntimeException e) {
      log.error("Upload failed: {}", e.getMessage(), e);
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(ErrorResponse.of("UPLOAD_FAILED", "Document upload failed",
              httpRequest.getHeader("X-Trace-ID")));
    }
  }

  // TODO: Implement grant, revoke, open-ticket, status endpoints

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