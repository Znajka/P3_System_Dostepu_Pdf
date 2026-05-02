package com.p3.dostepu.api.dto;

import java.time.ZonedDateTime;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * DTO for GET /documents/{id}/open-ticket response (200 OK).
 * Per API contract: returns temporary, single-use JWT ticket for FastAPI streaming.
 * Ticket is scoped to document, user, and microservice (aud=pdf-microservice).
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OpenTicketResponse {

  @JsonProperty("ticket")
  private String ticket;

  @JsonProperty("ticketId")
  private String ticketId;

  @JsonProperty("expiresAt")
  private ZonedDateTime expiresAt;

  @JsonProperty("issuedAt")
  private ZonedDateTime issuedAt;

  @JsonProperty("usage")
  private Usage usage;

  @Getter
  @Setter
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  public static class Usage {
    @JsonProperty("singleUse")
    private Boolean singleUse;

    @JsonProperty("aud")
    private String aud;

    @JsonProperty("documentId")
    private String documentId;

    @JsonProperty("userId")
    private String userId;
  }
}