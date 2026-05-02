package com.p3.dostepu.domain.repository;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.p3.dostepu.domain.entity.RateLimitState;

/**
 * Spring Data JPA repository for RateLimitState.
 */
@Repository
public interface RateLimitStateRepository extends JpaRepository<RateLimitState, UUID> {
  Optional<RateLimitState> findByUserId(UUID userId);
}