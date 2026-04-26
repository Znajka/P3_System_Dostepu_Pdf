package com.p3.dostepu.domain.entity;

import java.time.ZonedDateTime;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
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
 * DocumentKeyMetadata entity: stores per-document encryption key metadata
 * (DEK wrapped by KMS master key). CRITICAL SECURITY: wrapped_dek never plaintext,
 * stored encrypted. Wrap algorithm: AES-KW or RSA-OAEP. IV and tag for authenticated
 * encryption. Per CONTRIBUTING.md Key Management section.
 */
@Entity
@Table(name = "document_key_metadata")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(exclude = { "document" })
public class DocumentKeyMetadata {

  @Id
  @NotNull
  @Column(name = "document_id")
  private UUID documentId;

  @NotNull
  @Column(nullable = false)
  @JsonIgnore
  private byte[] wrappedDek;

  @NotBlank
  @Column(nullable = false, length = 50)
  @Builder.Default
  private String wrapAlgorithm = "AES-KW";

  @NotNull
  @Column(nullable = false)
  @JsonIgnore
  private byte[] iv;

  @NotNull
  @Column(nullable = false)
  @JsonIgnore
  private byte[] tag;

  @NotBlank
  @Column(nullable = false, length = 255)
  private String kmsKeyId;

  @Column(length = 50)
  private String kmsKeyVersion;

  @Column(columnDefinition = "jsonb")
  private String kmsMetadata;

  @CreationTimestamp
  @Column(nullable = false, updatable = false)
  private ZonedDateTime createdAt;

  // Relationships
  @OneToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "document_id", insertable = false, updatable = false)
  private Document document;
}