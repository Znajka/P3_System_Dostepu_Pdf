package com.p3.dostepu.security.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT validation utility for FastAPI with IP-pinning support.
 */
@Slf4j
@Component
public class JwtValidator {

  @Value("${app.jwt.secret:}")
  private String jwtSecret;

  private static final Pattern IPV4_PATTERN = Pattern.compile(
      "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
          + "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
  );

  private static final Pattern IPV6_PATTERN = Pattern.compile(
      "^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
  );

  /**
   * Validate JWT token and extract claims.
   */
  public Claims validateToken(String token) throws JwtException {
    try {
      return Jwts.parser()
          .verifyWith(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)))
          .build()
          .parseSignedClaims(token)
          .getPayload();
    } catch (JwtException e) {
      log.warn("Token validation failed: {}", e.getMessage());
      throw e;
    }
  }

  /**
   * Validate open-ticket JWT with IP-pinning check.
   */
  public Claims validateOpenTicketWithIpPinning(
      String token,
      String expectedDocumentId,
      String expectedUserId,
      String clientIp
  ) throws JwtException {
    try {
      Claims claims = validateToken(token);

      String[] requiredClaims = { "sub", "doc", "aud", "jti", "exp", "iat" };
      for (String claim : requiredClaims) {
        if (!claims.containsKey(claim)) {
          throw new JwtException("Missing required claim: " + claim);
        }
      }

      String audience = claims.get("aud", String.class);
      if (!"pdf-microservice".equals(audience)) {
        throw new JwtException("Invalid audience: " + audience + ", expected: pdf-microservice");
      }

      String tokenDocId = claims.get("doc", String.class);
      if (!tokenDocId.equals(expectedDocumentId)) {
        log.warn("Document ID mismatch: expected={}, actual={}", expectedDocumentId, tokenDocId);
        throw new JwtException("Document ID mismatch");
      }

      String tokenUserId = claims.getSubject();
      if (!tokenUserId.equals(expectedUserId)) {
        log.warn("User ID mismatch: expected={}, actual={}", expectedUserId, tokenUserId);
        throw new JwtException("User ID mismatch");
      }

      validateIpPinning(claims, clientIp);

      log.info(
          "Open-ticket validated successfully: user={}, doc={}, clientIp={}",
          tokenUserId, tokenDocId, clientIp
      );

      return claims;

    } catch (JwtException e) {
      log.error("Open-ticket validation failed: {}", e.getMessage());
      throw e;
    }
  }

  private void validateIpPinning(Claims claims, String clientIp) throws JwtException {
    Boolean ipPinningEnabled = (Boolean) claims.getOrDefault("ip_pinning_enabled", false);

    if (!ipPinningEnabled) {
      log.debug("IP pinning not enabled for this ticket");
      return;
    }

    String pinnedIp = claims.get("ip", String.class);

    if (pinnedIp == null || pinnedIp.isEmpty()) {
      log.warn("IP pinning enabled but no IP found in token");
      throw new JwtException("IP pinning violation: no pinned IP in token");
    }

    if (!isValidIpAddress(clientIp)) {
      log.warn("Invalid client IP format: {}", clientIp);
      throw new JwtException("Invalid IP address format");
    }

    if (!isValidIpAddress(pinnedIp)) {
      log.error("Invalid pinned IP format in token: {}", pinnedIp);
      throw new JwtException("Invalid pinned IP format in token");
    }

    if (!ipAddressesMatch(pinnedIp, clientIp)) {
      log.warn("IP mismatch: pinnedIp={}, clientIp={}", pinnedIp, clientIp);
      throw new JwtException(
          "IP mismatch: ticket pinned to " + maskIpAddress(pinnedIp)
              + ", current IP is " + maskIpAddress(clientIp)
      );
    }

    log.debug("IP pinning validation passed: ip={}", maskIpAddress(clientIp));
  }

  private boolean ipAddressesMatch(String ip1, String ip2) {
    if (ip1.equals(ip2)) {
      return true;
    }
    String normalizedIp1 = normalizeIpAddress(ip1);
    String normalizedIp2 = normalizeIpAddress(ip2);
    return normalizedIp1.equals(normalizedIp2);
  }

  private String normalizeIpAddress(String ip) {
    if (ip == null) {
      return null;
    }
    if (ip.startsWith("::ffff:")) {
      return ip.substring(7);
    }
    return ip;
  }

  private boolean isValidIpAddress(String ip) {
    if (ip == null || ip.isEmpty()) {
      return false;
    }
    if (IPV4_PATTERN.matcher(ip).matches()) {
      return true;
    }
    if (IPV6_PATTERN.matcher(ip).matches()) {
      return true;
    }
    if (ip.contains(":")) {
      return true;
    }
    return false;
  }

  private String maskIpAddress(String ip) {
    if (ip == null) {
      return "unknown";
    }
    if (ip.contains(":")) {
      int lastColon = ip.lastIndexOf(':');
      return ip.substring(0, lastColon) + ":****";
    } else {
      int lastDot = ip.lastIndexOf('.');
      if (lastDot > 0) {
        return ip.substring(0, lastDot) + ".*";
      }
    }
    return ip;
  }

  public Optional<String> getIpAddressFromToken(String token) {
    try {
      Claims claims = validateToken(token);
      return Optional.ofNullable(claims.get("ip", String.class));
    } catch (JwtException e) {
      return Optional.empty();
    }
  }
}   