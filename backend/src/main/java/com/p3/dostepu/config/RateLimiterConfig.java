package com.p3.dostepu.config;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Rate limiter cache configuration.
 * Uses Spring's ConcurrentMapCacheManager for simple in-memory caching.
 */
@Configuration
@EnableCaching
public class RateLimiterConfig {

  @Bean
  public CacheManager cacheManager() {
    return new ConcurrentMapCacheManager("rate_limit_buckets");
  }
}