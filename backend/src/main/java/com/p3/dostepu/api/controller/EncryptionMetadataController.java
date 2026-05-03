package com.p3.dostepu.api.controller;

import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.p3.dostepu.api.dto.EncryptionMetadataResponse;
import com.p3.dostepu.api.response.ErrorResponse;
import com.p3.dostepu.application.exception.ResourceNotFoundException;
import com.p3.dostepu.application.exception.UnauthorizedException;
import com.p3.dostepu.application.service.DocumentEncryptionMetadataService;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.repository.UserRepository;
import com.p3.dostepu.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Viewer encryption metadata (DEK + GCM nonce/tag) for ticketed streaming.
 */
@Slf4j
@RestController
@RequestMapping("/api/internal/documents")
@RequiredArgsConstructor
public class EncryptionMetadataController {

  private final DocumentEncryptionMetadataService encryptionMetadataService;
  private final UserRepository userRepository;

  @GetMapping("/{id}/encryption-metadata")
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<?> getEncryptionMetadata(
      @PathVariable("id") UUID documentId,
      HttpServletRequest httpRequest) {

    try {
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
      User user = userRepository.findById(userDetails.getUserId())
          .orElseThrow(() -> new RuntimeException("Authenticated user not found"));

      EncryptionMetadataResponse body =
          encryptionMetadataService.getEncryptionMetadata(documentId, user);
      return ResponseEntity.ok(body);

    } catch (ResourceNotFoundException e) {
      return ResponseEntity.status(HttpStatus.NOT_FOUND)
          .body(ErrorResponse.of("NOT_FOUND", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));
    } catch (UnauthorizedException e) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN)
          .body(ErrorResponse.of("FORBIDDEN", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));
    } catch (IllegalStateException e) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(ErrorResponse.of("METADATA_ERROR", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));
    } catch (Exception e) {
      log.error("encryption-metadata failed: {}", e.getMessage(), e);
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(ErrorResponse.of("METADATA_FAILED", "Failed to load encryption metadata",
              httpRequest.getHeader("X-Trace-ID")));
    }
  }
}
