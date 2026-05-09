package com.p3.dostepu.api.controller;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

/**
 * Proxies decrypted PDF streams from FastAPI on the same origin as the SPA
 * (:8080). Forwards {@code X-Forwarded-For} so ticket IP pinning matches what
 * Spring saw when issuing the open-ticket.
 */
@Slf4j
@RestController
@RequestMapping("/api/stream")
public class DocumentStreamProxyController {

  private final HttpClient httpClient = HttpClient.newBuilder()
      .connectTimeout(Duration.ofSeconds(10))
      .build();

  @Value("${fastapi.service.url:http://localhost:8443}")
  private String fastApiBaseUrl;

  @GetMapping("/pdf")
  public ResponseEntity<StreamingResponseBody> streamPdf(
      @RequestParam(value = "ticket", required = false) String ticketParam,
      @RequestHeader(value = "X-Document-Stream-Ticket", required = false)
          String ticketHeader,
      @RequestHeader(value = "X-DEK", required = false) String dek,
      @RequestHeader(value = "X-Nonce", required = false) String nonce,
      @RequestHeader(value = "X-Tag", required = false) String tag,
      @RequestHeader(value = "X-Chunk-Size", required = false) String chunkSize,
      HttpServletRequest servletRequest) {

    String ticket =
        (ticketHeader != null && !ticketHeader.isBlank())
            ? ticketHeader.trim()
            : (ticketParam != null ? ticketParam.trim() : null);
    if (ticket == null || ticket.isBlank()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
          "Missing ticket (use X-Document-Stream-Ticket or ticket query param)");
    }

    try {
      String base = fastApiBaseUrl.endsWith("/")
          ? fastApiBaseUrl.substring(0, fastApiBaseUrl.length() - 1)
          : fastApiBaseUrl;
      // Prefer header-based ticket at GET /stream (JWT-in-path decoding breaks signatures).
      URI upstream = URI.create(base + "/stream");

      String viewerIp = extractClientIp(servletRequest);

      HttpRequest.Builder ub = HttpRequest.newBuilder(upstream).timeout(Duration.ofMinutes(5))
          .GET();
      ub.header("X-Forwarded-For", viewerIp);
      ub.header("X-Document-Stream-Ticket", ticket);
      if (dek != null && !dek.isBlank()) {
        ub.header("X-DEK", dek);
      }
      if (nonce != null && !nonce.isBlank()) {
        ub.header("X-Nonce", nonce);
      }
      if (tag != null && !tag.isBlank()) {
        ub.header("X-Tag", tag);
      }
      ub.header("X-Chunk-Size",
          chunkSize != null && !chunkSize.isBlank() ? chunkSize : "65536");

      HttpResponse<InputStream> response =
          httpClient.send(ub.build(), HttpResponse.BodyHandlers.ofInputStream());

      int status = response.statusCode();
      if (status != 200) {
        byte[] errBody = response.body().readAllBytes();
        String msg = errBody.length > 0 ? new String(errBody, StandardCharsets.UTF_8) : "";
        log.warn("FastAPI stream rejected: http={}, snippet={}", status,
            msg.length() > 256 ? msg.substring(0, 256) : msg);
        HttpStatus st;
        try {
          st = HttpStatus.valueOf(status);
        } catch (IllegalArgumentException ex) {
          st = HttpStatus.BAD_GATEWAY;
        }
        throw new ResponseStatusException(st,
            msg.length() > 512 ? msg.substring(0, 512) + "…" : msg);
      }

      InputStream upstreamBody = response.body();
      StreamingResponseBody stream = os -> {
        try (InputStream in = upstreamBody) {
          in.transferTo(os);
        }
      };

      return ResponseEntity.ok()
          .contentType(MediaType.APPLICATION_PDF)
          .cacheControl(CacheControl.noStore())
          .header(HttpHeaders.PRAGMA, "no-cache")
          .header(HttpHeaders.EXPIRES, "0")
          .header("X-Content-Type-Options", "nosniff")
          .body(stream);

    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Stream interrupted");
    } catch (ResponseStatusException e) {
      throw e;
    } catch (Exception e) {
      log.error("Stream proxy failed: {}", e.getMessage(), e);
      throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Stream unavailable");
    }
  }

  private static String extractClientIp(HttpServletRequest request) {
    String xForwardedFor = request.getHeader("X-Forwarded-For");
    if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
      return xForwardedFor.split(",")[0].trim();
    }
    String xRealIp = request.getHeader("X-Real-IP");
    if (xRealIp != null && !xRealIp.isEmpty()) {
      return xRealIp.trim();
    }
    return request.getRemoteAddr();
  }
}
