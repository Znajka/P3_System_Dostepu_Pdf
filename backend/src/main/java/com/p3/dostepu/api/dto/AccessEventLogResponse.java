package com.p3.dostepu.api.dto;

import java.time.ZonedDateTime;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO for GET /logs/access-events response (paginated audit log).
 * Per API contract: total count, limit, offset, events array.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessEventLogResponse {

  @JsonProperty("total")
  private Long total;

  @JsonProperty("limit")
  private Integer limit;

  @JsonProperty("offset")
  private Integer offset;

  @JsonProperty("events")
  private List<EventEntry> events;

  @Getter
  @Setter
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  public static class EventEntry {
    @JsonProperty("id")
    private String id;

    @JsonProperty("timestamp")
    private ZonedDateTime timestamp;

    @JsonProperty("userId")
    private String userId;

    @JsonProperty("documentId")
    private String documentId;

    @JsonProperty("action")
    private String action;

    @JsonProperty("result")
    private String result;

    @JsonProperty("ip")
    private String ip;

    @JsonProperty("reason")
    private String reason;

    @JsonProperty("metadata")
    private String metadata;
  }
}