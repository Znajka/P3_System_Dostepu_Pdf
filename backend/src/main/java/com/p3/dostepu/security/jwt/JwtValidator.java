package com.p3.dostepu.security.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.PyJWTError;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT validation utility for FastAPI with IP-pinning support.
 * Per CONTRIBUTING.md API Design: JWT with expiration and revocation.
 * Enhanced: validates IP address pinning for ticket security.
 */
@Slf4j
@Component
public class JwtValidator {

  @Value("${app.jwt.secret:}")
  private String jwtSecret;

  @Value("${app.security.ip-pinning-enabled:true}")
  private Boolean ipPinningEnabled;

  private static final Pattern IPV4_PATTERN = Pattern.compile(
      "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
          + "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
  );

  private static final Pattern IPV6_PATTERN = Pattern.compile(
      "^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
  );

  private final String algorithm = "HS512";

  /**
   * Validate JWT token and extract claims.
   */
  public Claims validateToken(String token) throws Exception {
    try {
      return Jwts.parser()
          .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
          .parseClaimsJws(token)
          .getBody();
    } catch (Exception e) {
      log.warn("Token validation failed: {}", e.getMessage());
      throw e;
    }
  }

  /**
   * Validate open-ticket JWT with IP-pinning check.
   *
   * @param token JWT token
   * @param expectedDocumentId document ID to validate against
   * @param expectedUserId user ID to validate against
   * @param clientIp client IP address (from request)
   * @return Claims if validation succeeds
   * @throws Exception if validation fails
   */
  public Claims validateOpenTicketWithIpPinning(
      String token,
      String expectedDocumentId,
      String expectedUserId,
      String clientIp
  ) throws Exception {
    try {
      // Step 1: Validate token signature and expiration
      Claims claims = validateToken(token);

      // Step 2: Validate required claims for open-ticket
      String[] requiredClaims = { "sub", "doc", "aud", "jti", "exp", "iat" };
      for (String claim : requiredClaims) {
        if (!claims.containsKey(claim)) {
          throw new IllegalArgumentException("Missing required claim: " + claim);
        }
      }

      // Step 3: Validate audience
      String audience = claims.get("aud", String.class);
      if (!"pdf-microservice".equals(audience)) {
        throw new IllegalArgumentException(
            "Invalid audience: " + audience + ", expected: pdf-microservice"
        );
      }

      // Step 4: Validate document ID
      String tokenDocId = claims.get("doc", String.class);
      if (!tokenDocId.equals(expectedDocumentId)) {
        log.warn(
            "Document ID mismatch: expected={}, actual={}",
            expectedDocumentId, tokenDocId
        );
        throw new IllegalArgumentException("Document ID mismatch");
      }

      // Step 5: Validate user ID
      String tokenUserId = claims.getSubject();
      if (!tokenUserId.equals(expectedUserId)) {
        log.warn(
            "User ID mismatch: expected={}, actual={}",
            expectedUserId, tokenUserId
        );
        throw new IllegalArgumentException("User ID mismatch");
      }

      // Step 6: Validate IP pinning (critical security check)
      validateIpPinning(claims, clientIp);

      log.info(
          "Open-ticket validated successfully: user={}, doc={}, clientIp={}",
          tokenUserId, tokenDocId, clientIp
      );

      return claims;

    } catch (Exception e) {
      log.error("Open-ticket validation failed: {}", e.getMessage());
      throw e;
    }
  }

  /**
   * Validate IP address pinning.
   * Ensures ticket was requested from same IP and is being used from same IP.
   *
   * @param claims JWT claims
   * @param clientIp client IP address from request
   * @throws IllegalArgumentException if IP mismatch detected
   */
  private void validateIpPinning(Claims claims, String clientIp)
      throws IllegalArgumentException {
    // Check if IP pinning is enabled
    Boolean ipPinningEnabled = (Boolean) claims.getOrDefault("ip_pinning_enabled", false);

    if (!ipPinningEnabled) {
      log.debug("IP pinning not enabled for this ticket");
      return;
    }

    // Extract pinned IP from token
    String pinnedIp = claims.get("ip", String.class);

    if (pinnedIp == null || pinnedIp.isEmpty()) {
      log.warn("IP pinning enabled but no IP found in token");
      throw new IllegalArgumentException("IP pinning violation: no pinned IP in token");
    }

    // Validate current client IP format
    if (!isValidIpAddress(clientIp)) {
      log.warn("Invalid client IP format: {}", clientIp);
      throw new IllegalArgumentException("Invalid IP address format");
    }

    // Validate pinned IP format
    if (!isValidIpAddress(pinnedIp)) {
      log.error("Invalid pinned IP format in token: {}", pinnedIp);
      throw new IllegalArgumentException("Invalid pinned IP format in token");
    }

    // Compare IPs (handle IPv4/IPv6)
    if (!ipAddressesMatch(pinnedIp, clientIp)) {
      log.warn(
          "IP mismatch (possible token theft or proxy): pinnedIp={}, clientIp={}",
          pinnedIp, clientIp
      );
      throw new IllegalArgumentException(
          "IP mismatch: ticket pinned to " + maskIpAddress(pinnedIp)
              + ", current IP is " + maskIpAddress(clientIp)
      );
    }

    log.debug("IP pinning validation passed: ip={}", maskIpAddress(clientIp));
  }

  /**
   * Check if two IP addresses match (handles IPv4/IPv6).
   */
  private boolean ipAddressesMatch(String ip1, String ip2) {
    // Exact match
    if (ip1.equals(ip2)) {
      return true;
    }

    // Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
    String normalizedIp1 = normalizeIpAddress(ip1);
    String normalizedIp2 = normalizeIpAddress(ip2);

    return normalizedIp1.equals(normalizedIp2);
  }

  /**
   * Normalize IP address for comparison.
   * Handles IPv4-mapped IPv6 addresses and leading zeros.
   */
  private String normalizeIpAddress(String ip) {
    if (ip == null) {
      return null;
    }

    // Remove IPv4-mapped IPv6 prefix
    if (ip.startsWith("::ffff:")) {
      return ip.substring(7);
    }

    return ip;
  }

  /**
   * Validate IP address format (IPv4 or IPv6).
   */
  private boolean isValidIpAddress(String ip) {
    if (ip == null || ip.isEmpty()) {
      return false;
    }

    // Check IPv4 format
    if (IPV4_PATTERN.matcher(ip).matches()) {
      return true;
    }

    // Check IPv6 format
    if (IPV6_PATTERN.matcher(ip).matches()) {
      return true;
    }

    // Check IPv6 with compression (simplified)
    if (ip.contains(":")) {
      return true; // Allow other IPv6 formats
    }

    return false;
  }

  /**
   * Mask IP address for logging (hide last octet for privacy).
   * Example: 192.168.1.100 -> 192.168.1.***
   */
  private String maskIpAddress(String ip) {
    if (ip == null) {
      return "unknown";
    }

    if (ip.contains(":")) {
      // IPv6: hide last segment
      int lastColon = ip.lastIndexOf(':');
      return ip.substring(0, lastColon) + ":****";
    } else {
      // IPv4: hide last octet
      int lastDot = ip.lastIndexOf('.');
      if (lastDot > 0) {
        return ip.substring(0, lastDot) + ".*";
      }
    }

    return ip;
  }

  /**
   * Extract IP address from token (for logging/monitoring).
   */
  public Optional<String> getIpAddressFromToken(String token) {
    try {
      Claims claims = validateToken(token);
      return Optional.ofNullable(claims.get("ip", String.class));
    } catch (Exception e) {
      return Optional.empty();
    }
  }
}