package com.p3.dostepu.api.dto;

import java.util.Set;
import java.util.UUID;

public record AuthLoginResponse(
    UUID userId,
    String accessToken,
    String refreshToken,
    String tokenType,
    String username,
    Set<String> roles
) {
}
