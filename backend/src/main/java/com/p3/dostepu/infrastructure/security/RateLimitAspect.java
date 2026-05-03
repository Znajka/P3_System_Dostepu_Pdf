package com.p3.dostepu.infrastructure.security;

import java.util.UUID;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import com.p3.dostepu.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * AOP aspect to apply rate limiting to controller methods.
 * Per CONTRIBUTING.md: enforce rate limits on access-sensitive operations.
 */
@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class RateLimitAspect {

  private final RateLimiterService rateLimiterService;

  /**
   * Apply rate limiting before sensitive operations (grant, revoke, open-ticket).
   */
  @Before("execution(* com.p3.dostepu.application.service.*.*(..)) "
      + "&& ("
      + "execution(* *.grantAccess(..)) || "
      + "execution(* *.revokeAccess(..)) || "
      + "execution(* *.issueAccessTicket(..))"
      + ")")
  public void enforceRateLimit(JoinPoint joinPoint) {
    try {
      // Extract user from security context
      Object principal = SecurityContextHolder.getContext().getAuthentication()
          .getPrincipal();

      if (!(principal instanceof CustomUserDetails)) {
        log.warn("Rate limit check failed: principal is not CustomUserDetails");
        return;
      }

      CustomUserDetails userDetails = (CustomUserDetails) principal;
      UUID userId = userDetails.getUserId();
      String methodName = joinPoint.getSignature().getName();

      // Check rate limit
      rateLimiterService.checkRateLimit(userId, methodName);

    } catch (Exception ex) {
      log.error("Rate limit check error: {}", ex.getMessage(), ex);
      throw ex;
    }
  }
}