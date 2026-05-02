package com.p3.dostepu.domain.repository;

import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.p3.dostepu.domain.entity.DocumentKeyMetadata;

/**
 * Spring Data JPA repository for DocumentKeyMetadata.
 */
@Repository
public interface DocumentKeyMetadataRepository
    extends JpaRepository<DocumentKeyMetadata, UUID> {
}