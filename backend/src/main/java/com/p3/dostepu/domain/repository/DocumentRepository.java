package com.p3.dostepu.domain.repository;

import java.time.ZonedDateTime;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import com.p3.dostepu.domain.entity.Document;

/**
 * Spring Data JPA repository for Document entity.
 */
@Repository
public interface DocumentRepository extends JpaRepository<Document, UUID> {
  Optional<Document> findByIdAndDeletedAtNull(UUID id);

  Optional<Document> findByIdAndOwnerIdAndDeletedAtNull(UUID id, UUID ownerId);

  @Query("""
      SELECT DISTINCT d FROM Document d
      LEFT JOIN AccessGrant g ON g.document = d
        AND g.revoked = false
        AND g.expiresAt > :now
        AND g.granteeUser.id = :userId
      WHERE d.deletedAt IS NULL
        AND (d.owner.id = :userId OR g.id IS NOT NULL)
      """)
  Page<Document> findAccessibleForUser(@Param("userId") UUID userId,
      @Param("now") ZonedDateTime now, Pageable pageable);
}