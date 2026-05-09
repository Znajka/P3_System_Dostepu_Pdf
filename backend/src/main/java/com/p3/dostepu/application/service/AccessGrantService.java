package com.p3.dostepu.application.service;

import java.time.ZonedDateTime;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.p3.dostepu.api.dto.AccessGrantRequest;
import com.p3.dostepu.api.dto.AccessGrantResponse;
import com.p3.dostepu.api.dto.AccessRevokeRequest;
import com.p3.dostepu.application.exception.ConflictException;
import com.p3.dostepu.application.exception.ResourceNotFoundException;
import com.p3.dostepu.application.exception.UnauthorizedException;
import com.p3.dostepu.domain.entity.AccessAction;
import com.p3.dostepu.domain.entity.AccessEventLog;
import com.p3.dostepu.domain.entity.AccessGrant;
import com.p3.dostepu.domain.entity.AccessResult;
import com.p3.dostepu.domain.entity.Document;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.entity.UserRole;
import com.p3.dostepu.domain.repository.AccessEventLogRepository;
import com.p3.dostepu.domain.repository.AccessGrantRepository;
import com.p3.dostepu.domain.repository.DocumentRepository;
import com.p3.dostepu.domain.repository.UserRepository;
import org.springframework.dao.DataIntegrityViolationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * AccessGrantService with audit logging; grant/revoke by grantee username only.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccessGrantService {

  private final AccessGrantRepository grantRepository;
  private final DocumentRepository documentRepository;
  private final UserRepository userRepository;
  private final AccessEventLogRepository auditLogRepository;
  private final AuditLogService auditLogService;

  @Transactional
  public AccessGrantResponse grantAccess(UUID documentId, AccessGrantRequest request,
      User grantedBy, String clientIp) {

    UUID granteeUserId = null;
    try {
      Document document = documentRepository.findByIdAndDeletedAtNull(documentId)
          .orElseThrow(() -> new ResourceNotFoundException(
              "Document not found: " + documentId));

      if (!isAuthorizedToGrant(document, grantedBy)) {
        logAccessEvent(grantedBy.getId(), documentId, AccessAction.GRANT,
            AccessResult.FAILURE, clientIp, "Not authorized to grant access");
        throw new UnauthorizedException(
            "Only document owner or ADMIN can grant access");
      }

      final UUID resolvedGranteeUserId = resolveGranteeUserFromUsername(request);
      granteeUserId = resolvedGranteeUserId;

      User granteeUser = userRepository.findByIdAndActiveTrue(resolvedGranteeUserId)
          .orElseThrow(() -> new ResourceNotFoundException(
              "Grantee user not found or inactive: " + resolvedGranteeUserId));

      if (granteeUser.getId().equals(grantedBy.getId())) {
        throw new IllegalArgumentException(
            "You cannot grant access to yourself — owners and admins already have access.");
      }

      ZonedDateTime now = ZonedDateTime.now();
      grantRepository.revokeExpiredGrantsForDocumentAndGrantee(
          documentId, resolvedGranteeUserId, now,
          "Superseded: access period ended");

      ZonedDateTime validFrom = request.getValidFrom() != null
          ? request.getValidFrom()
          : now;
      if (!request.getExpiresAt().isAfter(validFrom)) {
        logAccessEvent(grantedBy.getId(), documentId, AccessAction.GRANT,
            AccessResult.FAILURE, clientIp, "expiresAt must be after validFrom");
        throw new IllegalArgumentException("expiresAt must be after validFrom");
      }
      if (!request.getExpiresAt().isAfter(now)) {
        logAccessEvent(grantedBy.getId(), documentId, AccessAction.GRANT,
            AccessResult.FAILURE, clientIp, "Expiration time is not in the future");
        throw new IllegalArgumentException(
            "Expiration time must be in the future");
      }

      Integer activeCount = grantRepository.countActiveGrants(documentId,
          resolvedGranteeUserId, now);
      if (activeCount != null && activeCount > 0) {
        logAccessEvent(grantedBy.getId(), documentId, AccessAction.GRANT,
            AccessResult.FAILURE, clientIp,
            "Active grant already exists for this grantee");
        throw new ConflictException(
            "Active grant already exists for this grantee and document");
      }

      AccessGrant grant = AccessGrant.builder()
          .document(document)
          .granteeUser(granteeUser)
          .grantedByUser(grantedBy)
          .validFrom(validFrom)
          .expiresAt(request.getExpiresAt())
          .revoked(false)
          .build();

      grant = grantRepository.save(grant);

      auditLogService.logGrant(grantedBy.getId(), granteeUser.getId(), documentId,
          request.getExpiresAt(), clientIp, null, true, null);

      return AccessGrantResponse.builder()
          .grantId(grant.getId())
          .documentId(grant.getDocument().getId())
          .granteeUserId(grant.getGranteeUser().getId())
          .grantedBy(grant.getGrantedByUser().getId())
          .validFrom(grant.getValidFrom())
          .expiresAt(grant.getExpiresAt())
          .createdAt(grant.getCreatedAt())
          .build();

    } catch (ConflictException | UnauthorizedException | ResourceNotFoundException e) {
      throw e;
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (DataIntegrityViolationException e) {
      log.warn(
          "Grant violates DB constraint: {}",
          e.getMostSpecificCause() != null
              ? e.getMostSpecificCause().getMessage() : e.getMessage());
      throw new ConflictException(
          "Cannot create grant: an existing grant record still applies. Wait for cleanup or revoke the previous grant.");
    } catch (Exception e) {
      log.error("Grant access failed: {}", e.getMessage(), e);
      UUID forAudit = granteeUserId != null ? granteeUserId : grantedBy.getId();
      auditLogService.logGrant(grantedBy.getId(), forAudit, documentId,
          request.getExpiresAt(), clientIp, null, false, e.getMessage());
      throw e;
    }
  }

  @Transactional
  public AccessGrantResponse revokeAccessByGrantId(UUID grantId, User revokedBy,
      String reason, String clientIp) {

    AccessGrant grant = grantRepository.findById(grantId)
        .orElseThrow(() -> new ResourceNotFoundException("Grant not found: " + grantId));

    Document document = documentRepository.findByIdAndDeletedAtNull(grant.getDocument().getId())
        .orElseThrow(() -> new ResourceNotFoundException(
            "Document not found: " + grant.getDocument().getId()));

    if (!isAuthorizedToGrant(document, revokedBy)) {
      logAccessEvent(revokedBy.getId(), document.getId(), AccessAction.REVOKE,
          AccessResult.FAILURE, clientIp, "Not authorized to revoke access");
      throw new UnauthorizedException("Only document owner or ADMIN can revoke access");
    }

    if (Boolean.TRUE.equals(grant.getRevoked())) {
      throw new ConflictException("Grant is already revoked");
    }

    grant.revoke(revokedBy, reason);
    grantRepository.save(grant);

    auditLogService.logRevoke(revokedBy.getId(), grant.getGranteeUser().getId(),
        document.getId(), reason, clientIp, null);

    return AccessGrantResponse.builder()
        .grantId(grant.getId())
        .documentId(document.getId())
        .granteeUserId(grant.getGranteeUser().getId())
        .grantedBy(grant.getGrantedByUser().getId())
        .validFrom(grant.getValidFrom())
        .expiresAt(grant.getExpiresAt())
        .createdAt(grant.getCreatedAt())
        .build();
  }

  @Transactional
  public AccessGrantResponse revokeAccess(UUID documentId, AccessRevokeRequest request,
      User revokedBy, String clientIp) {

    UUID granteeUserId = resolveGranteeFromRevokeRequest(request);

    try {
      Document document = documentRepository.findByIdAndDeletedAtNull(documentId)
          .orElseThrow(() -> new ResourceNotFoundException(
              "Document not found: " + documentId));

      if (!isAuthorizedToGrant(document, revokedBy)) {
        logAccessEvent(revokedBy.getId(), documentId, AccessAction.REVOKE,
            AccessResult.FAILURE, clientIp, "Not authorized to revoke access");
        throw new UnauthorizedException(
            "Only document owner or ADMIN can revoke access");
      }

      ZonedDateTime now = ZonedDateTime.now();
      AccessGrant grant = grantRepository
          .findRevocableGrant(documentId, granteeUserId, now)
          .orElseThrow(() -> new ResourceNotFoundException(
              "Active grant not found for document and grantee"));

      grant.revoke(revokedBy, request.getReason());
      grant = grantRepository.save(grant);

      auditLogService.logRevoke(revokedBy.getId(), granteeUserId, documentId,
          request.getReason(), clientIp, null);

      return AccessGrantResponse.builder()
          .grantId(grant.getId())
          .documentId(grant.getDocument().getId())
          .granteeUserId(grant.getGranteeUser().getId())
          .grantedBy(grant.getGrantedByUser().getId())
          .validFrom(grant.getValidFrom())
          .expiresAt(grant.getExpiresAt())
          .createdAt(grant.getCreatedAt())
          .build();

    } catch (UnauthorizedException | ResourceNotFoundException e) {
      throw e;
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception e) {
      log.error("Revoke access failed: {}", e.getMessage(), e);
      throw e;
    }
  }

  /**
   * Permanently removes a grant row from the document.
   * If the grant is still active (not revoked), logs a revoke first so access ends in audit.
   */
  @Transactional
  public void deleteGrantForDocument(UUID documentId, UUID grantId, User deletedBy,
      String clientIp) {
    AccessGrant grant = grantRepository.findByDocument_IdAndId(documentId, grantId)
        .orElseThrow(() -> new ResourceNotFoundException(
            "Grant not found for this document: " + grantId));

    Document document = documentRepository.findByIdAndDeletedAtNull(documentId)
        .orElseThrow(() -> new ResourceNotFoundException(
            "Document not found: " + documentId));

    if (isAuthorizedToGrant(document, deletedBy)) {
      UUID granteeId = grant.getGranteeUser().getId();
      if (!Boolean.TRUE.equals(grant.getRevoked())) {
        auditLogService.logRevoke(deletedBy.getId(), granteeId, documentId,
            "Grant removed — access revoked and record deleted", clientIp, null);
      }
      grantRepository.delete(grant);
      return;
    }

    if (grant.getGranteeUser().getId().equals(deletedBy.getId())) {
      ZonedDateTime now = ZonedDateTime.now();
      boolean expired = !grant.getExpiresAt().isAfter(now);
      boolean revoked = Boolean.TRUE.equals(grant.getRevoked());
      if (!expired && !revoked) {
        throw new UnauthorizedException(
            "You can remove this entry only after your access has expired or been revoked");
      }
      grantRepository.delete(grant);
      return;
    }

    logAccessEvent(deletedBy.getId(), documentId, AccessAction.REVOKE,
        AccessResult.FAILURE, clientIp, "Not authorized to remove grant");
    throw new UnauthorizedException(
        "Only the document owner, an administrator, or the grantee (for expired "
            + "or revoked grants) can remove grant records");
  }

  private UUID resolveGranteeUserFromUsername(AccessGrantRequest request) {
    String username = request.getGranteeUsername();
    if (isBlank(username)) {
      throw new IllegalArgumentException("granteeUsername is required");
    }
    return userRepository.findByUsernameIgnoreCase(username.trim())
        .orElseThrow(() -> new ResourceNotFoundException(
            "Grantee not found for username: " + username.trim()))
        .getId();
  }

  private UUID resolveGranteeFromRevokeRequest(AccessRevokeRequest request) {
    String username = request.getGranteeUsername();
    if (isBlank(username)) {
      throw new IllegalArgumentException("granteeUsername is required");
    }
    return userRepository.findByUsernameIgnoreCase(username.trim())
        .orElseThrow(() -> new ResourceNotFoundException(
            "Grantee not found for username: " + username.trim()))
        .getId();
  }

  private static boolean isBlank(String s) {
    return s == null || s.trim().isEmpty();
  }

  private boolean isAuthorizedToGrant(Document document, User user) {
    boolean isOwner = document.getOwner().getId().equals(user.getId());
    boolean isAdmin = user.getRoles().contains(UserRole.ADMIN);
    return isOwner || isAdmin;
  }

  private void logAccessEvent(UUID userId, UUID documentId, AccessAction action,
      AccessResult result, String clientIp, String reason) {
    try {
      AccessEventLog event = AccessEventLog.builder()
          .user(userId != null ? userRepository.getReferenceById(userId) : null)
          .document(documentId != null ? documentRepository.getReferenceById(documentId)
              : null)
          .action(action)
          .result(result)
          .ipAddress(clientIp)
          .reason(reason)
          .timestampUtc(ZonedDateTime.now())
          .build();

      auditLogRepository.save(event);
    } catch (Exception e) {
      log.error("Failed to log access event: {}", e.getMessage());
    }
  }
}
