package com.p3.dostepu.application.util;

import java.time.ZonedDateTime;
import com.p3.dostepu.domain.entity.AccessGrant;

public final class AccessShareStatus {

  private AccessShareStatus() {}

  /** PENDING, ACTIVE, EXPIRED, or REVOKED. */
  public static String forGrant(AccessGrant g, ZonedDateTime now) {
    if (Boolean.TRUE.equals(g.getRevoked())) {
      return "REVOKED";
    }
    if (!g.getExpiresAt().isAfter(now)) {
      return "EXPIRED";
    }
    if (g.getValidFrom().isAfter(now)) {
      return "PENDING";
    }
    return "ACTIVE";
  }
}
