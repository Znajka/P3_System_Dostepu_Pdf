package com.p3.dostepu.domain.entity;

import java.time.ZonedDateTime;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * SessionToken entity: stores server-side session or token metadata for revocation.
 * Token hashes stored (never plaintext tokens in DB). Used for session invalidation
 * and refresh token rotation per CONTRIBUTING.md API Design.
 */
@Entity
@Table(name = "session_token")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(exclude = { "user" })
public class SessionToken {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @NotNull
  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "user_id", nullable = false)
  private User user;

  @NotBlank
  @Column(nullable = false, unique = true, length = 255)
  private String tokenHash;

  @Column(nullable = false, length = 50)
  @Builder.Default
  private String tokenType = "Bearer";

  @NotNull
  @Column(nullable = false, updatable = false)
  private ZonedDateTime issuedAt;

  @NotNull
  @Column(nullable = false)
  private ZonedDateTime expiresAt;

  @Column(nullable = false)
  @Builder.Default
  private Boolean revoked = false;

  @Column(name = "revoked_at")
  private ZonedDateTime revokedAt;

  @Column(name = "ip_address", columnDefinition = "inet")
  private String ipAddress;

  @Column(length = 512)
  private String userAgent;

  @Column(length = 255, unique = true)
  private String jti;

  @CreationTimestamp
  @Column(nullable = false, updatable = false)
  private ZonedDateTime createdAt;

  public boolean isExpired() {
    return expiresAt.isBefore(ZonedDateTime.now());
  }

  public boolean isValid() {
    return !revoked && !isExpired();
  }

  public void revoke() {
    this.revoked = true;
    this.revokedAt = ZonedDateTime.now();
  }
}