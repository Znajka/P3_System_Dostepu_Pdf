package com.p3.dostepu.domain.entity;

import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * User entity: stores user identity, roles, password hash, and rate-limit/lockout state.
 * Passwords are hashed with bcrypt/Argon2 (never plaintext). Rate-limiting: tracks
 * failed_attempts and lock_until for account lockout per CONTRIBUTING.md requirements.
 */
@Entity
@Table(name = "\"user\"")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(exclude = { "documents", "grantedAccess", "sessionTokens", 
    "accessEvents" })
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @NotBlank
  @Column(nullable = false, unique = true, length = 255)
  private String username;

  @NotBlank
  @Email
  @Column(nullable = false, unique = true, length = 255)
  private String email;

  @NotBlank
  @Column(nullable = false, length = 255)
  private String passwordHash;

  @ElementCollection(fetch = FetchType.EAGER)
  @Enumerated(EnumType.STRING)
  @Column(nullable = false)
  @Builder.Default
  private Set<UserRole> roles = new HashSet<>();

  @Column(nullable = false)
  @Builder.Default
  private Integer failedAttempts = 0;

  @Column(name = "lock_until")
  private ZonedDateTime lockUntil;

  @Column(nullable = false)
  @Builder.Default
  private Boolean active = true;

  @CreationTimestamp
  @Column(nullable = false, updatable = false)
  private ZonedDateTime createdAt;

  @UpdateTimestamp
  @Column(nullable = false)
  private ZonedDateTime updatedAt;

  @Column(name = "deleted_at")
  private ZonedDateTime deletedAt;

  // Relationships
  @OneToMany(mappedBy = "owner", fetch = FetchType.LAZY)
  private Set<Document> documents = new HashSet<>();

  @OneToMany(mappedBy = "granteeUser", fetch = FetchType.LAZY)
  private Set<AccessGrant> grantedAccess = new HashSet<>();

  @OneToMany(mappedBy = "grantedByUser", fetch = FetchType.LAZY)
  private Set<AccessGrant> grantsCreated = new HashSet<>();

  @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
  private Set<SessionToken> sessionTokens = new HashSet<>();

  @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
  private Set<AccessEventLog> accessEvents = new HashSet<>();

  @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
  private Set<RateLimitState> rateLimitState = new HashSet<>();

  public boolean isLocked() {
    return lockUntil != null && lockUntil.isAfter(ZonedDateTime.now());
  }

  public void lock(Integer lockoutMinutes) {
    this.lockUntil = ZonedDateTime.now().plusMinutes(lockoutMinutes);
  }

  public void unlock() {
    this.lockUntil = null;
    this.failedAttempts = 0;
  }
}