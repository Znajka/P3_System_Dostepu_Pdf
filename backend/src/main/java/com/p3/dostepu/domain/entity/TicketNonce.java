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
 * TicketNonce entity: stores single-use ticket nonces to prevent replay attacks.
 * Nonce = jti (JWT ID) from open-ticket response. Marked as used after first
 * successful FastAPI validation. Expires after ticket TTL + buffer.
 */
@Entity
@Table(name = "ticket_nonce")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(exclude = { "document", "user" })
public class TicketNonce {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @NotBlank
  @Column(nullable = false, unique = true, length = 255)
  private String nonce;

  @NotNull
  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "document_id", nullable = false)
  private Document document;

  @NotNull
  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "user_id", nullable = false)
  private User user;

  @Column(nullable = false)
  @Builder.Default
  private Boolean used = false;

  @Column(name = "used_at")
  private ZonedDateTime usedAt;

  @NotNull
  @Column(nullable = false)
  private ZonedDateTime expiresAt;

  @CreationTimestamp
  @Column(nullable = false, updatable = false)
  private ZonedDateTime createdAt;

  public boolean isExpired() {
    return expiresAt.isBefore(ZonedDateTime.now());
  }

  public boolean isValidForUse() {
    return !used && !isExpired();
  }

  public void markUsed() {
    this.used = true;
    this.usedAt = ZonedDateTime.now();
  }
}