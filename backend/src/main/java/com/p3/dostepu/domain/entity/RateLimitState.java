package com.p3.dostepu.domain.entity;

import java.time.ZonedDateTime;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * RateLimitState entity: tracks per-user failed attempts for open-ticket requests.
 * Resets on successful grant-based access; incremented on failures. Used to enforce
 * lockout policy (N failures in window -> lock_until) per CONTRIBUTING.md
 * Rate Limiting & Lockout Policy.
 */
@Entity
@Table(name = "rate_limit_state")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(exclude = { "user" })
public class RateLimitState {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @NotNull
  @OneToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "user_id", nullable = false, unique = true)
  private User user;

  @Column(nullable = false)
  @Builder.Default
  private Integer failedAttempts = 0;

  @Column(name = "last_failed_attempt")
  private ZonedDateTime lastFailedAttempt;

  @Column(name = "lock_until")
  private ZonedDateTime lockUntil;

  @Column(name = "reset_at")
  private ZonedDateTime resetAt;

  @CreationTimestamp
  @Column(nullable = false, updatable = false)
  private ZonedDateTime createdAt;

  @UpdateTimestamp
  @Column(nullable = false)
  private ZonedDateTime updatedAt;

  public void incrementFailedAttempts() {
    this.failedAttempts++;
    this.lastFailedAttempt = ZonedDateTime.now();
  }

  public void resetAttempts() {
    this.failedAttempts = 0;
    this.lastFailedAttempt = null;
    this.lockUntil = null;
    this.resetAt = ZonedDateTime.now();
  }

  public boolean isLocked() {
    return lockUntil != null && lockUntil.isAfter(ZonedDateTime.now());
  }
}