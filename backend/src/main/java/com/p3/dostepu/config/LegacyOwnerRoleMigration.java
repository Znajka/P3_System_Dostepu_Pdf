package com.p3.dostepu.config;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Older DBs may still store {@code OWNER} in {@code user_roles}. The Java {@code UserRole}
 * enum no longer defines OWNER, which breaks Hibernate on load. Map those rows to {@code USER}.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class LegacyOwnerRoleMigration {

  private final JdbcTemplate jdbcTemplate;

  @Bean
  @Order(Integer.MIN_VALUE)
  ApplicationRunner migrateLegacyOwnerRoleValues() {
    return args -> {
      try {
        Integer n = jdbcTemplate.queryForObject(
            """
            SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = current_schema() AND table_name = 'user_roles'
            """,
            Integer.class);
        if (n == null || n == 0) {
          return;
        }
        int updated = jdbcTemplate.update(
            """
            UPDATE user_roles SET roles = 'USER'::user_role
            WHERE CAST(roles AS VARCHAR) = 'OWNER'
            """);
        if (updated > 0) {
          log.warn("Migrated {} user_roles rows from OWNER to USER", updated);
        }
      } catch (Exception e) {
        log.warn("Legacy OWNER migration skipped: {}", e.getMessage());
      }
    };
  }
}
