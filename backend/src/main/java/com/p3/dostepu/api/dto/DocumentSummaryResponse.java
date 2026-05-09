package com.p3.dostepu.api.dto;

import java.time.ZonedDateTime;
import java.util.UUID;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DocumentSummaryResponse {

  @JsonProperty("documentId")
  private UUID documentId;

  @JsonProperty("title")
  private String title;

  @JsonProperty("ownerId")
  private UUID ownerId;

  @JsonProperty("createdAt")
  private ZonedDateTime createdAt;

  /** Present for {@code scope=shared}: latest non-revoked grant for the current user. */
  @JsonProperty("grantId")
  private UUID grantId;

  @JsonProperty("validFrom")
  private ZonedDateTime validFrom;

  @JsonProperty("expiresAt")
  private ZonedDateTime expiresAt;

  @JsonProperty("shareStatus")
  private String shareStatus;
}
