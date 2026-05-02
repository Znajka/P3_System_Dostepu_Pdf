package com.p3.dostepu.api.controller;

import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.p3.dostepu.api.dto.AccessEventLogRequest;
import com.p3.dostepu.api.dto.AccessEventLogResponse;
import com.p3.dostepu.api.response.ErrorResponse;
import com.p3.dostepu.application.service.AuditLogService;
import com.p3.dostepu.domain.entity.AccessAction;
import com.p3.dostepu.domain.entity.AccessEventLog;
import com.p3.dostepu.domain.entity.AccessResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import java.time.ZonedDateTime;

/**
 * Audit Log API controller: handles access event log queries.
 * Endpoint:
 *   GET /api/logs/access-events - query audit logs (ADMIN only)
 * Per CONTRIBUTING.md: ADMIN or Auditor role required.
 */
@Slf4j
@RestController
@RequestMapping("/api/logs")
@RequiredArgsConstructor
public class AuditLogController {

  private final AuditLogService auditLogService;

  /**
   * GET /api/logs/access-events - Query access event logs.
   * Admin-only endpoint. Returns paginated audit events with optional filters.
   * Filters: documentId, userId, action, result, from/to timestamps.
   *
   * @param documentId optional document filter (UUID)
   * @param userId optional user filter (UUID)
   * @param action optional action filter (upload, grant, revoke, open_attempt,
   *        stream_start, stream_end)
   * @param result optional result filter (success, failure)
   * @param from optional start timestamp (ISO 8601 UTC)
   * @param to optional end timestamp (ISO 8601 UTC)
   * @param limit page size (1-1000, default 100)
   * @param offset page offset (default 0)
   * @param httpRequest HTTP request
   * @return AccessEventLogResponse with paginated events
   */
  @GetMapping("/access-events")
  @PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<?> getAccessEvents(
      @RequestParam(value = "documentId", required = false) String documentId,
      @RequestParam(value = "userId", required = false) String userId,
      @RequestParam(value = "action", required = false) String action,
      @RequestParam(value = "result", required = false) String result,
      @RequestParam(value = "from", required = false) ZonedDateTime from,
      @RequestParam(value = "to", required = false) ZonedDateTime to,
      @RequestParam(value = "limit", defaultValue = "100") Integer limit,
      @RequestParam(value = "offset", defaultValue = "0") Integer offset,
      HttpServletRequest httpRequest) {

    try {
      // Validate limit
      if (limit < 1 || limit > 1000) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(ErrorResponse.of("BAD_REQUEST", "Limit must be between 1 and 1000",
                httpRequest.getHeader("X-Trace-ID")));
      }

      // Validate offset
      if (offset < 0) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(ErrorResponse.of("BAD_REQUEST", "Offset must be >= 0",
                httpRequest.getHeader("X-Trace-ID")));
      }

      // Parse filters
      UUID parsedDocumentId = null;
      if (documentId != null) {
        try {
          parsedDocumentId = UUID.fromString(documentId);
        } catch (IllegalArgumentException e) {
          return ResponseEntity.status(HttpStatus.BAD_REQUEST)
              .body(ErrorResponse.of("BAD_REQUEST",
                  "Invalid documentId format: " + e.getMessage(),
                  httpRequest.getHeader("X-Trace-ID")));
        }
      }

      UUID parsedUserId = null;
      if (userId != null) {
        try {
          parsedUserId = UUID.fromString(userId);
        } catch (IllegalArgumentException e) {
          return ResponseEntity.status(HttpStatus.BAD_REQUEST)
              .body(ErrorResponse.of("BAD_REQUEST",
                  "Invalid userId format: " + e.getMessage(),
                  httpRequest.getHeader("X-Trace-ID")));
        }
      }

      AccessAction parsedAction = null;
      if (action != null) {
        try {
          parsedAction = AccessAction.valueOf(action.toUpperCase());
        } catch (IllegalArgumentException e) {
          return ResponseEntity.status(HttpStatus.BAD_REQUEST)
              .body(ErrorResponse.of("BAD_REQUEST",
                  "Invalid action: " + action, httpRequest.getHeader("X-Trace-ID")));
        }
      }

      AccessResult parsedResult = null;
      if (result != null) {
        try {
          parsedResult = AccessResult.valueOf(result.toUpperCase());
        } catch (IllegalArgumentException e) {
          return ResponseEntity.status(HttpStatus.BAD_REQUEST)
              .body(ErrorResponse.of("BAD_REQUEST",
                  "Invalid result: " + result, httpRequest.getHeader("X-Trace-ID")));
        }
      }

      log.info(
          "Query access events: documentId={}, userId={}, action={}, result={}, "
              + "from={}, to={}, limit={}, offset={}",
          parsedDocumentId, parsedUserId, parsedAction, parsedResult, from, to, limit,
          offset);

      // Query events
      Page<AccessEventLog> events = auditLogService.queryEvents(parsedDocumentId,
          parsedUserId, parsedAction, parsedResult, from, to, offset / limit, limit);

      // Map to response DTO
      AccessEventLogResponse response = AccessEventLogResponse.builder()
          .total(events.getTotalElements())
          .limit(limit)
          .offset(offset)
          .events(events.getContent().stream()
              .map(event -> AccessEventLogResponse.EventEntry.builder()
                  .id(event.getId().toString())
                  .timestamp(event.getTimestampUtc())
                  .userId(
                      event.getUser() != null ? event.getUser().getId().toString() : null)
                  .documentId(event.getDocument() != null
                      ? event.getDocument().getId().toString()
                      : null)
                  .action(event.getAction().toString())
                  .result(event.getResult().toString())
                  .ip(event.getIpAddress())
                  .reason(event.getReason())
                  .metadata(event.getMetadata())
                  .build())
              .collect(Collectors.toList()))
          .build();

      return ResponseEntity.ok(response);

    } catch (Exception e) {
      log.error("Failed to query access events: {}", e.getMessage(), e);
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
          .body(ErrorResponse.of("QUERY_FAILED", "Failed to query access events",
              httpRequest.getHeader("X-Trace-ID")));
    }
  }
}