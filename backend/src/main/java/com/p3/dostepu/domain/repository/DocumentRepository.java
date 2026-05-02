package com.p3.dostepu.domain.repository;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.p3.dostepu.domain.entity.Document;

/**
 * Spring Data JPA repository for Document entity.
 */
@Repository
public interface DocumentRepository extends JpaRepository<Document, UUID> {
  Optional<Document> findByIdAndDeletedAtNull(UUID id);

  Optional<Document> findByIdAndOwnerIdAndDeletedAtNull(UUID id, UUID ownerId);
}