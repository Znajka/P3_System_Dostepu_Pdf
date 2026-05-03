package com.p3.dostepu.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DEK + AES-GCM nonce/tag for client-side streaming (base64).
 * Returned only when caller has valid access to the document.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EncryptionMetadataResponse {

  @JsonProperty("dek")
  private String dek;

  @JsonProperty("nonce")
  private String nonce;

  @JsonProperty("tag")
  private String tag;

  @JsonProperty("algorithm")
  private String algorithm;
}
