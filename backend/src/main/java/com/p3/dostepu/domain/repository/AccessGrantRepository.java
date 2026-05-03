package com.p3.dostepu.domain.repository;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import com.p3.dostepu.domain.entity.AccessGrant;

/**
 * Spring Data JPA repository for AccessGrant entity.
 */
@Repository
public interface AccessGrantRepository extends JpaRepository<AccessGrant, UUID> {
  /**
   * Find active grant for a document and grantee (not revoked, not expired).
   */
  Optional<AccessGrant> findByDocumentIdAndGranteeUserIdAndRevokedFalseAndExpiresAtAfter(
      UUID documentId, UUID granteeUserId, ZonedDateTime now);

  /**
   * Find all grants for a document (active and inactive).
   */
  List<AccessGrant> findByDocumentIdOrderByCreatedAtDesc(UUID documentId);

  /**
   * Find all grants for a grantee (active and inactive).
   */
  List<AccessGrant> findByGranteeUserIdOrderByCreatedAtDesc(UUID granteeUserId);

  /**
   * Count active grants for a document-grantee pair.
   */
  @Query("SELECT COUNT(ag) FROM AccessGrant ag WHERE ag.document.id = :documentId "
      + "AND ag.granteeUser.id = :granteeUserId AND ag.revoked = false "
      + "AND ag.expiresAt > :now")
  Integer countActiveGrants(@Param("documentId") UUID documentId,
      @Param("granteeUserId") UUID granteeUserId, @Param("now") ZonedDateTime now);

  /**
   * Find expired grants that have not been revoked.
   * Used by scheduled task to automatically revoke expired access.
   * Per CONTRIBUTING.md: Documents inaccessible after expiration.
   */
  @Query("SELECT ag FROM AccessGrant ag WHERE ag.revoked = false "
      + "AND ag.expiresAt <= :now ORDER BY ag.expiresAt ASC")
  List<AccessGrant> findExpiredAndNotRevokedGrants(@Param("now") ZonedDateTime now);

  /**
   * Count expired grants (for monitoring).
   */
  @Query("SELECT COUNT(ag) FROM AccessGrant ag WHERE ag.revoked = false "
      + "AND ag.expiresAt <= :now")
  Long countExpiredGrants(@Param("now") ZonedDateTime now);

  /**
   * Find grants expiring within N days (for proactive notifications).
   */
  @Query("SELECT ag FROM AccessGrant ag WHERE ag.revoked = false "
      + "AND ag.expiresAt > :now AND ag.expiresAt <= :soon "
      + "ORDER BY ag.expiresAt ASC")
  List<AccessGrant> findExpiringWithinDays(@Param("now") ZonedDateTime now,
      @Param("soon") ZonedDateTime soon);
}