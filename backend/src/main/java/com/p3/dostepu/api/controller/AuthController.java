package com.p3.dostepu.api.controller;

import java.util.stream.Collectors;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.p3.dostepu.api.dto.AuthLoginRequest;
import com.p3.dostepu.api.dto.AuthLoginResponse;
import com.p3.dostepu.security.CustomUserDetails;
import com.p3.dostepu.security.jwt.JwtProvider;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@Validated
@RequiredArgsConstructor
public class AuthController {

  private final AuthenticationManager authenticationManager;
  private final JwtProvider jwtProvider;

  @PostMapping("/login")
  public ResponseEntity<AuthLoginResponse> login(@Valid @RequestBody AuthLoginRequest request) {
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(request.username(), request.password()));

    CustomUserDetails user = (CustomUserDetails) authentication.getPrincipal();
    String accessToken = jwtProvider.generateAccessToken(authentication);
    String refreshToken = jwtProvider.generateRefreshToken(user.getUserId().toString(),
        user.getUsername());

    return ResponseEntity.ok(new AuthLoginResponse(
        user.getUserId(),
        accessToken,
        refreshToken,
        "Bearer",
        user.getUsername(),
        user.getAuthorities().stream()
            .map(auth -> auth.getAuthority().replace("ROLE_", ""))
            .collect(Collectors.toSet())));
  }
}
