package com.p3.dostepu.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;

/**
 * Rate limiter configuration using Bucket4j and Caffeine cache.
 * Per CONTRIBUTING.md: rate-limit 5 failed attempts in 15 minutes -> 30-minute lockout.
 */
@Slf4j
@Configuration
@EnableCaching
public class RateLimiterConfig {

  /**
   * Caffeine cache manager for rate limiting (local cache).
   * Alternative: use Redis for distributed systems.
   */
  @Bean
  public CacheManager cacheManager() {
    CaffeineCacheManager cacheManager = new CaffeineCacheManager(
        "rate_limit_buckets",
        "user_lockout"
    );

    cacheManager.setCaffeine(Caffeine.newBuilder()
        .maximumSize(10000)
        .expireAfterWrite(1, TimeUnit.HOURS)
        .recordStats()
        .build());

    log.info("Initialized Caffeine cache manager for rate limiting");
    return cacheManager;
  }
}