package com.p3.dostepu.api.controller;

import java.util.UUID;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.p3.dostepu.api.dto.TicketMarkUsedRequest;
import com.p3.dostepu.api.response.ErrorResponse;
import com.p3.dostepu.application.service.DocumentAccessService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service-to-service ticket consumption (replay prevention).
 */
@Slf4j
@RestController
@RequestMapping("/api/internal/tickets")
@RequiredArgsConstructor
public class InternalTicketController {

  private final DocumentAccessService documentAccessService;

  @Value("${app.internal.api-key:}")
  private String internalApiKey;

  @PostMapping("/mark-used")
  public ResponseEntity<?> markTicketUsed(
      @RequestHeader(value = "X-Internal-Api-Key", required = false) String apiKey,
      @Valid @RequestBody TicketMarkUsedRequest request,
      HttpServletRequest httpRequest) {

    if (internalApiKey == null || internalApiKey.isBlank()) {
      log.warn("Internal API key not configured; rejecting mark-used");
      return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
          .body(ErrorResponse.of("NOT_CONFIGURED", "Internal API not configured",
              httpRequest.getHeader("X-Trace-ID")));
    }
    if (apiKey == null || !internalApiKey.equals(apiKey)) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .body(ErrorResponse.of("UNAUTHORIZED", "Invalid internal API key",
              httpRequest.getHeader("X-Trace-ID")));
    }

    try {
      UUID userId = UUID.fromString(request.getUserId());
      boolean ok = documentAccessService.markTicketAsUsed(request.getNonce(), userId);
      if (!ok) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
            .body(ErrorResponse.of("TICKET_INVALID", "Ticket not found, expired, or already used",
                httpRequest.getHeader("X-Trace-ID")));
      }
      return ResponseEntity.ok().build();
    } catch (IllegalArgumentException e) {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST)
          .body(ErrorResponse.of("BAD_REQUEST", "Invalid userId",
              httpRequest.getHeader("X-Trace-ID")));
    }
  }
}
