package com.p3.dostepu.api.controller;

import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;
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
import com.p3.dostepu.api.dto.AccessGrantResponse;
import com.p3.dostepu.api.dto.RevokeByGrantIdRequest;
import com.p3.dostepu.api.response.ErrorResponse;
import com.p3.dostepu.application.exception.ConflictException;
import com.p3.dostepu.application.exception.ResourceNotFoundException;
import com.p3.dostepu.application.exception.UnauthorizedException;
import com.p3.dostepu.application.service.AccessGrantService;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.repository.UserRepository;
import com.p3.dostepu.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * POST /api/grants/{grantId}/revoke — revoke by grant id (document owner or ADMIN).
 */
@Slf4j
@RestController
@RequestMapping("/api/grants")
@RequiredArgsConstructor
public class GrantRevokeController {

  private final AccessGrantService grantService;
  private final UserRepository userRepository;

  @PostMapping("/{grantId}/revoke")
  @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
  public ResponseEntity<?> revokeByGrantId(
      @PathVariable("grantId") UUID grantId,
      @RequestBody(required = false) RevokeByGrantIdRequest body,
      HttpServletRequest httpRequest) {

    try {
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
      UUID userId = userDetails.getUserId();
      User revokedBy = userRepository.findById(userId)
          .orElseThrow(() -> new RuntimeException("Authenticated user not found"));
      String reason = body != null ? body.getReason() : null;
      String clientIp = clientIp(httpRequest);

      AccessGrantResponse response = grantService.revokeAccessByGrantId(grantId, revokedBy,
          reason, clientIp);
      return ResponseEntity.ok(response);

    } catch (ResourceNotFoundException e) {
      return ResponseEntity.status(HttpStatus.NOT_FOUND)
          .body(ErrorResponse.of("NOT_FOUND", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));
    } catch (UnauthorizedException e) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN)
          .body(ErrorResponse.of("FORBIDDEN", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));
    } catch (ConflictException e) {
      return ResponseEntity.status(HttpStatus.CONFLICT)
          .body(ErrorResponse.of("CONFLICT", e.getMessage(),
              httpRequest.getHeader("X-Trace-ID")));
    } catch (Exception e) {
      log.error("Revoke by grant id failed: {}", e.getMessage(), e);
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(ErrorResponse.of("REVOKE_FAILED", "Failed to revoke grant",
              httpRequest.getHeader("X-Trace-ID")));
    }
  }

  private static String clientIp(HttpServletRequest req) {
    String xff = req.getHeader("X-Forwarded-For");
    if (xff != null && !xff.isBlank()) {
      return xff.split(",")[0].trim();
    }
    return req.getRemoteAddr();
  }
}
