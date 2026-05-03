package com.p3.dostepu.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TicketMarkUsedRequest {

  @NotBlank
  @JsonProperty("nonce")
  private String nonce;

  @NotBlank
  @JsonProperty("userId")
  private String userId;
}
