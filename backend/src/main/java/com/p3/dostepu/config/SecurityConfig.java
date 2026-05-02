package com.p3.dostepu.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration
    .AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration
    .EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.p3.dostepu.security.jwt.JwtAuthenticationFilter;
import com.p3.dostepu.security.jwt.JwtEntryPoint;
import lombok.RequiredArgsConstructor;

/**
 * Security configuration: JWT-based authentication, Bcrypt password hashing,
 * and role-based access control (ADMIN, USER, OWNER). Per CONTRIBUTING.md
 * Security Requirements and API Design.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

  private final UserDetailsService userDetailsService;
  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final JwtEntryPoint jwtEntryPoint;

  @Value("${app.jwt.secret:}")
  private String jwtSecret;

  /**
   * Password encoder: BCrypt with strength 12 (configurable via properties).
   * Per CONTRIBUTING.md: use bcrypt or Argon2 with salt.
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12);
  }

  /**
   * Authentication provider: DAO-based with BCrypt password encoder.
   */
  @Bean
  public DaoAuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService);
    authProvider.setPasswordEncoder(passwordEncoder());
    return authProvider;
  }

  /**
   * Authentication manager: manages authentication requests.
   */
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
      throws Exception {
    return config.getAuthenticationManager();
  }

  /**
   * Security filter chain: JWT-based stateless authentication.
   * - Stateless session: no session cookies, JWT in Authorization header.
   * - CORS: allow cross-origin requests (configure origins per environment).
   * - CSRF: disabled for stateless JWT (no session-based attacks).
   * - Public endpoints: login, register, actuator health.
   * - Protected endpoints: /documents/*, /logs/* require ADMIN role.
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        // Disable CSRF (stateless JWT, no session cookies)
        .csrf(csrf -> csrf.disable())
        // Use stateless session (no JSESSIONID cookie)
        .sessionManagement(session -> session.sessionCreationPolicy(
            SessionCreationPolicy.STATELESS))
        // CORS configuration
        .cors(cors -> cors.configurationSource(request -> {
          var corsConfig = new org.springframework.web.cors.CorsConfiguration();
          corsConfig.setAllowedOriginPatterns(
              java.util.List.of("http://localhost:*", "http://127.0.0.1:*"));
          corsConfig.setAllowedMethods(
              java.util.List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
          corsConfig.setAllowedHeaders(java.util.List.of("*"));
          corsConfig.setAllowCredentials(true);
          corsConfig.setMaxAge(3600L);
          return corsConfig;
        }))
        // Exception handling
        .exceptionHandling(exception -> exception
            .authenticationEntryPoint(jwtEntryPoint))
        // Authorization rules
        .authorizeHttpRequests(authz -> authz
            // Public endpoints
            .requestMatchers("/", "/api/auth/login", "/api/auth/register",
                "/api/auth/refresh").permitAll()
            .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
            .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()
            // Admin-only endpoints
            .requestMatchers(HttpMethod.GET, "/api/logs/access-events")
                .hasRole("ADMIN")
            // Document endpoints: owner/admin can create/grant/revoke
            .requestMatchers(HttpMethod.POST, "/api/documents")
                .hasAnyRole("ADMIN", "OWNER", "USER")
            .requestMatchers(HttpMethod.POST, "/api/documents/*/grant")
                .hasAnyRole("ADMIN", "OWNER")
            .requestMatchers(HttpMethod.POST, "/api/documents/*/revoke")
                .hasAnyRole("ADMIN", "OWNER")
            // Document access: any authenticated user with valid grant
            .requestMatchers(HttpMethod.GET, "/api/documents/*/open-ticket")
                .authenticated()
            .requestMatchers(HttpMethod.GET, "/api/documents/*/status")
                .authenticated()
            // Catch-all: require authentication
            .anyRequest().authenticated())
        // Add JWT filter
        .addFilterBefore(jwtAuthenticationFilter,
            UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }
}