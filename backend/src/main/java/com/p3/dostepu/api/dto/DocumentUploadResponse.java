package com.p3.dostepu.api.dto;

import java.time.ZonedDateTime;
import java.util.UUID;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO for POST /documents response (201 Created).
 * Returns document ID, owner, creation timestamp, and status.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DocumentUploadResponse {

  @JsonProperty("documentId")
  private UUID documentId;

  @JsonProperty("ownerId")
  private UUID ownerId;

  @JsonProperty("createdAt")
  private ZonedDateTime createdAt;

  @JsonProperty("status")
  @Builder.Default
  private String status = "uploaded";
}