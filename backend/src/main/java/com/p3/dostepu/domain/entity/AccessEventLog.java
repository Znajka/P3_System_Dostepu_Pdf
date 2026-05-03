package com.p3.dostepu.domain.entity;

import java.time.ZonedDateTime;
import java.util.UUID;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

/**
 * AccessEventLog entity: APPEND-ONLY audit log recording all security-relevant
 * events. Events: upload, grant, revoke, open_attempt, stream_start, stream_end.
 * IMMUTABLE: no updates or deletes after insertion (enforce at application level).
 * Per CONTRIBUTING.md Logging & Auditing requirements.
 */
@Entity
@Table(name = "access_event_log", indexes = {
    @Index(name = "idx_access_event_log_timestamp_utc", columnList = "timestamp_utc DESC"),
    @Index(name = "idx_access_event_log_user_id", columnList = "user_id"),
    @Index(name = "idx_access_event_log_document_id", columnList = "document_id"),
    @Index(name = "idx_access_event_log_action", columnList = "action"),
    @Index(name = "idx_access_event_log_result", columnList = "result")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(exclude = { "user", "document" })
public class AccessEventLog {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @NotNull
  @Column(nullable = false, updatable = false)
  private ZonedDateTime timestampUtc;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "user_id")
  private User user;

  @ManyToOne(fetch = FetchType.LAZY)
  @JoinColumn(name = "document_id")
  private Document document;

  @NotNull
  @Enumerated(EnumType.STRING)
  @Column(nullable = false, updatable = false)
  private AccessAction action;

  @NotNull
  @Enumerated(EnumType.STRING)
  @Column(nullable = false, updatable = false)
  private AccessResult result;

  @Column(name = "ip_address", columnDefinition = "inet")
  private String ipAddress;

  @Column(length = 512, updatable = false)
  private String userAgent;

  @Column(length = 255, updatable = false)
  private String reason;

  @Column(columnDefinition = "jsonb", updatable = false)
  private String metadata;

  @CreationTimestamp
  @Column(nullable = false, updatable = false)
  private ZonedDateTime createdAt;

  @PrePersist
  protected void onPersist() {
    if (timestampUtc == null) {
      timestampUtc = ZonedDateTime.now();
    }
    if (createdAt == null) {
      createdAt = ZonedDateTime.now();
    }
  }
}