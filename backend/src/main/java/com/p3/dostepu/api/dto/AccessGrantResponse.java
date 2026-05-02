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
 * DTO for POST /documents/{id}/grant response (200 OK).
 * Returns grant metadata: ID, document, grantee, expiry, creation timestamp.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessGrantResponse {

  @JsonProperty("grantId")
  private UUID grantId;

  @JsonProperty("documentId")
  private UUID documentId;

  @JsonProperty("granteeUserId")
  private UUID granteeUserId;

  @JsonProperty("grantedBy")
  private UUID grantedBy;

  @JsonProperty("expiresAt")
  private ZonedDateTime expiresAt;

  @JsonProperty("createdAt")
  private ZonedDateTime createdAt;
}