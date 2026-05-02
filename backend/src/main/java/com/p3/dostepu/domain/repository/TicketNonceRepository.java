package com.p3.dostepu.domain.repository;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.p3.dostepu.domain.entity.TicketNonce;

/**
 * Spring Data JPA repository for TicketNonce.
 */
@Repository
public interface TicketNonceRepository extends JpaRepository<TicketNonce, UUID> {
  Optional<TicketNonce> findByNonceAndUsedFalseAndExpiresAtAfter(
      String nonce, java.time.ZonedDateTime now);
}