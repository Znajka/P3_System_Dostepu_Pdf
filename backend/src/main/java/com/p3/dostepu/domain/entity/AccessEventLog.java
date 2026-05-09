package com.p3.dostepu.domain.entity;

import java.time.ZonedDateTime;
import java.util.UUID;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Convert;
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
import com.p3.dostepu.domain.converter.AccessActionAttributeConverter;
import com.p3.dostepu.domain.converter.AccessResultAttributeConverter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

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
  @Convert(converter = AccessActionAttributeConverter.class)
  @Column(nullable = false, updatable = false, length = 32)
  private AccessAction action;

  @NotNull
  @Convert(converter = AccessResultAttributeConverter.class)
  @Column(nullable = false, updatable = false, length = 16)
  private AccessResult result;

  @Column(name = "ip_address", length = 64)
  private String ipAddress;

  @Column(length = 512, updatable = false)
  private String userAgent;

  @Column(length = 255, updatable = false)
  private String reason;

  @JdbcTypeCode(SqlTypes.JSON)
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