package com.p3.dostepu.api.dto;

import java.time.ZonedDateTime;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO for POST /documents/{id}/grant request.
 * Provide exactly one of: granteeUserId, granteeUsername, granteeEmail.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessGrantRequest {

  @JsonProperty("granteeUserId")
  private String granteeUserId;

  @JsonProperty("granteeUsername")
  private String granteeUsername;

  @JsonProperty("granteeEmail")
  private String granteeEmail;

  @NotNull
  @JsonProperty("expiresAt")
  private ZonedDateTime expiresAt;

  @JsonProperty("note")
  private String note;
}