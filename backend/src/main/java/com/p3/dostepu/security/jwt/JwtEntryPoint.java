package com.p3.dostepu.security.jwt;

import java.io.IOException;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.p3.dostepu.api.response.ErrorResponse;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT authentication entry point: handles authentication errors (401).
 * Returns structured error response instead of default 401 page.
 */
@Slf4j
@Component
public class JwtEntryPoint implements AuthenticationEntryPoint {

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public void commence(
      HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse,
      AuthenticationException e) throws IOException, ServletException {

    log.error("Responding with unauthorized error. Message - {}", e.getMessage());

    httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
    httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

    ErrorResponse errorResponse = ErrorResponse.of(
    "UNAUTHORIZED", 
    "Unauthorized: " + e.getMessage(), 
    httpServletRequest.getHeader("X-Trace-ID")
    );

    httpServletResponse.getWriter().write(objectMapper.writeValueAsString(errorResponse));
  }
}