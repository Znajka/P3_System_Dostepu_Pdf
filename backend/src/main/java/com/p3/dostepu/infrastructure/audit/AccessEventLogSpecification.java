package com.p3.dostepu.infrastructure.audit;

import java.time.ZonedDateTime;
import java.util.UUID;
import org.springframework.data.jpa.domain.Specification;
import com.p3.dostepu.domain.entity.AccessAction;
import com.p3.dostepu.domain.entity.AccessEventLog;
import com.p3.dostepu.domain.entity.AccessResult;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;

/**
 * JPA Specification for AccessEventLog queries with flexible filtering.
 */
public class AccessEventLogSpecification {

  /**
   * Build dynamic specification from filters.
   */
  public static Specification<AccessEventLog> withFilters(UUID userId, UUID documentId,
      AccessAction action, AccessResult result, ZonedDateTime fromTimestamp,
      ZonedDateTime toTimestamp) {

    return (Root<AccessEventLog> root, CriteriaQuery<?> query,
        CriteriaBuilder cb) -> {
      Predicate predicate = cb.conjunction();

      if (userId != null) {
        predicate = cb.and(predicate, cb.equal(root.get("user").get("id"), userId));
      }

      if (documentId != null) {
        predicate =
            cb.and(predicate, cb.equal(root.get("document").get("id"), documentId));
      }

      if (action != null) {
        predicate = cb.and(predicate, cb.equal(root.get("action"), action));
      }

      if (result != null) {
        predicate = cb.and(predicate, cb.equal(root.get("result"), result));
      }

      if (fromTimestamp != null) {
        predicate = cb.and(predicate,
            cb.greaterThanOrEqualTo(root.get("timestampUtc"), fromTimestamp));
      }

      if (toTimestamp != null) {
        predicate = cb.and(predicate,
            cb.lessThanOrEqualTo(root.get("timestampUtc"), toTimestamp));
      }

      return predicate;
    };
  }
}