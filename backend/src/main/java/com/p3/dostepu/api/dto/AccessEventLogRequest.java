package com.p3.dostepu.api.dto;

import java.time.ZonedDateTime;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO for GET /logs/access-events request (query filters).
 * Per API contract: optional filters for documentId, userId, action, result, date range.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessEventLogRequest {

  @JsonProperty("documentId")
  private String documentId;

  @JsonProperty("userId")
  private String userId;

  @JsonProperty("action")
  private String action;

  @JsonProperty("result")
  private String result;

  @JsonProperty("from")
  private ZonedDateTime from;

  @JsonProperty("to")
  private ZonedDateTime to;

  @JsonProperty("limit")
  @Min(1)
  @Max(1000)
  @Builder.Default
  private Integer limit = 100;

  @JsonProperty("offset")
  @Min(0)
  @Builder.Default
  private Integer offset = 0;
}