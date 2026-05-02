package com.p3.dostepu.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO for POST /documents request body.
 * Metadata transmitted as JSON; file as multipart/form-data.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DocumentUploadRequest {

  @NotBlank
  @Size(min = 1, max = 255)
  private String title;

  @Size(max = 4000)
  private String description;

  @JsonProperty("tags")
  private String[] tags;

  @JsonProperty("visibleTo")
  @Builder.Default
  private String visibleTo = "private";
}