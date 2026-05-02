package com.p3.dostepu.security.jwt;

import java.io.IOException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.p3.dostepu.api.response.ErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT authentication entry point: handles unauthenticated requests
 * (missing or invalid token) by returning 401 Unauthorized with error JSON.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtEntryPoint implements AuthenticationEntryPoint {

  private final ObjectMapper objectMapper;

  @Override
  public void commence(HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse, AuthenticationException e)
      throws IOException, ServletException {
    log.error("Responding with unauthorized error. Message: {}", e.getMessage());

    httpServletResponse.setContentType("application/json;charset=UTF-8");
    httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

    ErrorResponse errorResponse = ErrorResponse.builder()
        .code("UNAUTHORIZED")
        .message("Authentication token is missing or invalid")
        .traceId(httpServletRequest.getHeader("X-Trace-ID"))
        .build();

    httpServletResponse.getWriter()
        .write(objectMapper.writeValueAsString(errorResponse));
  }
}