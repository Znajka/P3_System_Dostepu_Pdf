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
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * AccessGrant entity: stores document access grants (which user has access to
 * which document). expires_at enforced server-side; access revoked by setting
 * revoked flag. Only OWNER or ADMIN can grant/revoke per CONTRIBUTING.md API Design.
 */
@Entity
@Table(name = "access_grant")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(exclude = { "document", "granteeUser", "grantedByUser", 
    "revokedByUser" })
public class AccessGrant {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @NotNull
  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "document_id", nullable = false)
  private Document document;

  @NotNull
  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "grantee_user_id", nullable = false)
  private User granteeUser;

  @NotNull
  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "granted_by_user_id", nullable = false)
  private User grantedByUser;

  @NotNull
  @Column(nullable = false)
  private ZonedDateTime expiresAt;

  @Column(nullable = false)
  @Builder.Default
  private Boolean revoked = false;

  @Column(name = "revoked_at")
  private ZonedDateTime revokedAt;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "revoked_by_user_id")
  private User revokedByUser;

  @Column(length = 255)
  private String revokeReason;

  @CreationTimestamp
  @Column(nullable = false, updatable = false)
  private ZonedDateTime createdAt;

  @UpdateTimestamp
  @Column(nullable = false)
  private ZonedDateTime updatedAt;

  public boolean isActive() {
    return !revoked && expiresAt.isAfter(ZonedDateTime.now());
  }

  public void revoke(User revokedBy, String reason) {
    this.revoked = true;
    this.revokedAt = ZonedDateTime.now();
    this.revokedByUser = revokedBy;
    this.revokeReason = reason;
  }
}