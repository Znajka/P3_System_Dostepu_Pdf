package com.p3.dostepu.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO for POST /documents/{id}/revoke request.
 * Per API contract: granteeUserId (required), optional reason.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessRevokeRequest {

  @NotBlank
  @JsonProperty("granteeUserId")
  private String granteeUserId;

  @JsonProperty("reason")
  private String reason;
}