package com.p3.dostepu.security.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import com.p3.dostepu.domain.entity.UserRole;
import com.p3.dostepu.security.CustomUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT token provider: issues, validates, and extracts claims from JWT tokens.
 * - Algorithm: HS512 (HMAC with SHA-512).
 * - Expiration: configurable via properties (default 1 hour).
 * - Claims: sub (user id), roles, iat, exp, jti (unique token id).
 * Per CONTRIBUTING.md API Design: JWT with rotation and expiration.
 */
@Slf4j
@Component
public class JwtProvider {

  @Value("${app.jwt.secret:}")
  private String jwtSecret;

  @Value("${app.jwt.expiration-ms:3600000}")
  private Integer jwtExpirationMs;

  @Value("${app.jwt.refresh-token-expiration-ms:604800000}")
  private Integer refreshTokenExpirationMs;

  /**
   * Generate JWT access token from authentication.
   */
  public String generateAccessToken(Authentication authentication) {
    CustomUserDetails userPrincipal = (CustomUserDetails) authentication.getPrincipal();
    String roles = userPrincipal.getAuthorities()
        .stream()
        .map(auth -> auth.getAuthority().replace("ROLE_", ""))
        .collect(Collectors.joining(","));

    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtExpirationMs);

    return Jwts.builder()
        .setSubject(userPrincipal.getUserId().toString())
        .claim("roles", roles)
        .claim("username", userPrincipal.getUsername())
        .setIssuedAt(now)
        .setExpiration(expiryDate)
        .signWith(SignatureAlgorithm.HS512, jwtSecret.getBytes(StandardCharsets.UTF_8))
        .compact();
  }

  /**
   * Generate JWT refresh token (longer expiration).
   */
  public String generateRefreshToken(String userId, String username) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + refreshTokenExpirationMs);

    return Jwts.builder()
        .setSubject(userId)
        .claim("username", username)
        .claim("type", "refresh")
        .setIssuedAt(now)
        .setExpiration(expiryDate)
        .signWith(SignatureAlgorithm.HS512, jwtSecret.getBytes(StandardCharsets.UTF_8))
        .compact();
  }

  /**
   * Generate single-use document access ticket (short TTL, scoped to document).
   * Per API contract: ticket for /documents/{id}/open-ticket endpoint.
   */
  public String generateDocumentAccessTicket(String userId, String documentId,
      String nonce, Integer ttlSeconds) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + (ttlSeconds * 1000L));

    return Jwts.builder()
        .setSubject(userId)
        .claim("doc", documentId)
        .claim("aud", "pdf-microservice")
        .claim("jti", nonce)
        .claim("nonce", nonce)
        .claim("scopes", "open:document")
        .setIssuedAt(now)
        .setExpiration(expiryDate)
        .signWith(SignatureAlgorithm.HS512, jwtSecret.getBytes(StandardCharsets.UTF_8))
        .compact();
  }

  /**
   * Validate JWT token.
   */
  public boolean validateToken(String authToken) {
    try {
      Jwts.parser()
          .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
          .parseClaimsJws(authToken);
      return true;
    } catch (SignatureException e) {
      log.error("Invalid JWT signature: {}", e.getMessage());
    } catch (MalformedJwtException e) {
      log.error("Invalid JWT token: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      log.error("Unsupported JWT token: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      log.error("JWT claims string is empty: {}", e.getMessage());
    }
    return false;
  }

  /**
   * Extract user ID from JWT token.
   */
  public String getUserIdFromJwt(String token) {
    Claims claims = Jwts.parser()
        .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
        .parseClaimsJws(token)
        .getBody();
    return claims.getSubject();
  }

  /**
   * Extract roles from JWT token.
   */
  public Set<UserRole> getRolesFromJwt(String token) {
    Claims claims = Jwts.parser()
        .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
        .parseClaimsJws(token)
        .getBody();
    String rolesStr = claims.get("roles", String.class);
    if (rolesStr == null || rolesStr.isEmpty()) {
      return Set.of();
    }
    return Set.of(rolesStr.split(","))
        .stream()
        .map(UserRole::valueOf)
        .collect(Collectors.toSet());
  }

  /**
   * Extract expiration date from JWT token.
   */
  public Date getExpirationDateFromJwt(String token) {
    Claims claims = Jwts.parser()
        .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
        .parseClaimsJws(token)
        .getBody();
    return claims.getExpiration();
  }

  /**
   * Check if token is expired.
   */
  public boolean isTokenExpired(String token) {
    try {
      Date expiration = getExpirationDateFromJwt(token);
      return expiration.before(new Date());
    } catch (Exception e) {
      return true;
    }
  }
}