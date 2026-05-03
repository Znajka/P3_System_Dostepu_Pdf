package com.p3.dostepu.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for revoking document access.
 * Provide exactly one of: granteeUserId, granteeUsername, granteeEmail.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessRevokeRequest {

  @JsonProperty("granteeUserId")
  private String granteeUserId;

  @JsonProperty("granteeUsername")
  private String granteeUsername;

  @JsonProperty("granteeEmail")
  private String granteeEmail;

  private String reason;
}	