package com.p3.dostepu.domain.entity;

import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Document entity: stores document metadata, owner reference, and encrypted blob
 * location. Encrypted PDF blob is stored externally (object store or filesystem).
 * blob_path references the encrypted file location (not directly accessible).
 */
@Entity
@Table(name = "document")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(exclude = { "owner", "keyMetadata", "accessGrants", 
    "accessEvents", "ticketNonces" })
public class Document {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @NotNull
  @ManyToOne(fetch = FetchType.EAGER)
  @JoinColumn(name = "owner_id", nullable = false)
  private User owner;

  @NotBlank
  @Column(nullable = false, length = 255)
  private String title;

  @Column(length = 4000)
  private String description;

  @Column(columnDefinition = "VARCHAR(255)[]")
  private String[] tags;

  @NotBlank
  @Column(nullable = false, length = 511)
  private String blobPath;

  @NotNull
  @Positive
  @Column(nullable = false)
  private Long blobSizeBytes;

  @Column(nullable = false, length = 50)
  @Builder.Default
  private String encryptedAlgorithm = "AES-256-GCM";

  @CreationTimestamp
  @Column(nullable = false, updatable = false)
  private ZonedDateTime createdAt;

  @UpdateTimestamp
  @Column(nullable = false)
  private ZonedDateTime updatedAt;

  @Column(name = "deleted_at")
  private ZonedDateTime deletedAt;

  // Relationships
  @OneToOne(mappedBy = "document", cascade = CascadeType.REMOVE, fetch = FetchType.LAZY)
  private DocumentKeyMetadata keyMetadata;

  @OneToMany(mappedBy = "document", cascade = CascadeType.REMOVE, fetch = FetchType.LAZY)
  private Set<AccessGrant> accessGrants = new HashSet<>();

  @OneToMany(mappedBy = "document", fetch = FetchType.LAZY)
  private Set<AccessEventLog> accessEvents = new HashSet<>();

  @OneToMany(mappedBy = "document", cascade = CascadeType.REMOVE, fetch = FetchType.LAZY)
  private Set<TicketNonce> ticketNonces = new HashSet<>();

  public boolean isDeleted() {
    return deletedAt != null;
  }
}