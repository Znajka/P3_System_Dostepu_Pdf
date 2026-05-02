package com.p3.dostepu.domain.repository;

import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;
import com.p3.dostepu.domain.entity.AccessEventLog;

/**
 * Spring Data JPA repository for AccessEventLog (append-only audit log).
 * Supports both simple queries and dynamic filtering via Specification.
 */
@Repository
public interface AccessEventLogRepository
    extends JpaRepository<AccessEventLog, UUID>, JpaSpecificationExecutor<AccessEventLog> {
}