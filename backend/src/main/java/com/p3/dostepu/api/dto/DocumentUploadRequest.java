package com.p3.dostepu.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO for POST /documents multipart metadata (optional fields).
 * Document title is taken from the uploaded file's original name.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DocumentUploadRequest {

  @Size(max = 4000)
  private String description;

  @JsonProperty("tags")
  private String[] tags;

  @JsonProperty("visibleTo")
  @Builder.Default
  private String visibleTo = "private";
}