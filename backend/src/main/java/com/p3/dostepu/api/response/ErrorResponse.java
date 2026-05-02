package com.p3.dostepu.api.response;

import java.time.ZonedDateTime;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Global error response format (per API contract).
 * code: machine-readable error code (e.g., UNAUTHORIZED, FORBIDDEN, NOT_FOUND).
 * message: human-friendly short message.
 * details: optional structured details (field, reason).
 * traceId: server trace id for debugging.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {

  @JsonProperty("error")
  private Error error;

  @Getter
  @Setter
  @NoArgsConstructor
  @AllArgsConstructor
  @Builder
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class Error {
    private String code;
    private String message;
    private Details details;
    private String traceId;
    private ZonedDateTime timestamp;
  }

  @Getter
  @Setter
  @NoArgsConstructor
  @AllArgsConstructor
  public static class Details {
    private String field;
    private String reason;
  }

  // Convenience factory method
  public static ErrorResponse of(String code, String message, String traceId) {
    return ErrorResponse.builder()
        .error(Error.builder()
            .code(code)
            .message(message)
            .traceId(traceId)
            .timestamp(ZonedDateTime.now())
            .build())
        .build();
  }
}