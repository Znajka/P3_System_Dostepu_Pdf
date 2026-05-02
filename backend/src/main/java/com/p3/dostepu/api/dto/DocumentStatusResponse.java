package com.p3.dostepu.api.dto;

import java.time.ZonedDateTime;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO for GET /documents/{id}/status response (200 OK).
 * Shows document metadata and user's effective access status.
 * Grantee sees limited view (their grant expiry).
 * Owner/Admin see full details (list of all grants).
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DocumentStatusResponse {

  @JsonProperty("documentId")
  private String documentId;

  @JsonProperty("title")
  private String title;

  @JsonProperty("ownerId")
  private String ownerId;

  @JsonProperty("createdAt")
  private ZonedDateTime createdAt;

  @JsonProperty("accessible")
  private Boolean accessible;

  @JsonProperty("access")
  private AccessInfo access;

  @JsonProperty("grants")
  private List<GrantInfo> grants;

  @JsonProperty("locked")
  private Boolean locked;

  @Getter
  @Setter
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  public static class AccessInfo {
    @JsonProperty("granteeUserId")
    private String granteeUserId;

    @JsonProperty("expiresAt")
    private ZonedDateTime expiresAt;
  }

  @Getter
  @Setter
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  public static class GrantInfo {
    @JsonProperty("grantId")
    private String grantId;

    @JsonProperty("granteeUserId")
    private String granteeUserId;

    @JsonProperty("expiresAt")
    private ZonedDateTime expiresAt;

    @JsonProperty("revoked")
    private Boolean revoked;
  }
}