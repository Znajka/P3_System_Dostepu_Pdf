package com.p3.dostepu.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.context.annotation.Bean;
import lombok.extern.slf4j.Slf4j;

/**
 * Scheduling configuration for Spring Boot tasks.
 * Per CONTRIBUTING.md: ensure background tasks run with proper logging and error handling.
 */
@Slf4j
@Configuration
@EnableScheduling
public class SchedulingConfig {

  /**
   * Configure thread pool for scheduled tasks.
   */
  @Bean
  public ThreadPoolTaskScheduler taskScheduler() {
    ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
    scheduler.setPoolSize(5);
    scheduler.setThreadNamePrefix("p3-scheduled-");
    scheduler.setAwaitTerminationSeconds(60);
    scheduler.setWaitForTasksToCompleteOnShutdown(true);
    scheduler.initialize();

    log.info("Initialized ThreadPoolTaskScheduler with pool size: 5");
    return scheduler;
  }
}