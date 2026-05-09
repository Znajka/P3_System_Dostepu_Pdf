package com.p3.dostepu.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for revoking document access by grantee username.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessRevokeRequest {

  @NotBlank
  @JsonProperty("granteeUsername")
  private String granteeUsername;

  private String reason;
}
