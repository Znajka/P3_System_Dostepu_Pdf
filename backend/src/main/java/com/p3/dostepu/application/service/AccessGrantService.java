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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * AccessGrantService with audit logging and grantee resolution by id/username/email.
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

      granteeUserId = resolveGranteeUserId(request);

      User granteeUser = userRepository.findByIdAndActiveTrue(granteeUserId)
          .orElseThrow(() -> new ResourceNotFoundException(
              "Grantee user not found or inactive: " + granteeUserId));

      ZonedDateTime now = ZonedDateTime.now();
      if (!request.getExpiresAt().isAfter(now)) {
        logAccessEvent(grantedBy.getId(), documentId, AccessAction.GRANT,
            AccessResult.FAILURE, clientIp, "Expiration time is not in the future");
        throw new IllegalArgumentException(
            "Expiration time must be in the future");
      }

      Integer activeCount = grantRepository.countActiveGrants(documentId, granteeUserId,
          now);
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
          .expiresAt(grant.getExpiresAt())
          .createdAt(grant.getCreatedAt())
          .build();

    } catch (ConflictException | UnauthorizedException | ResourceNotFoundException e) {
      throw e;
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (Exception e) {
      log.error("Grant access failed: {}", e.getMessage(), e);
      UUID forAudit = granteeUserId != null ? granteeUserId : grantedBy.getId();
      auditLogService.logGrant(grantedBy.getId(), forAudit, documentId,
          request.getExpiresAt(), clientIp, null, false, e.getMessage());
      throw e;
    }
  }

  @Transactional
  public AccessGrantResponse revokeAccess(UUID documentId, AccessRevokeRequest request,
      User revokedBy, String clientIp) {

    UUID granteeUserId = resolveGranteeUserId(request);

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
          .findByDocumentIdAndGranteeUserIdAndRevokedFalseAndExpiresAtAfter(
              documentId, granteeUserId, now)
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

  private UUID resolveGranteeUserId(AccessGrantRequest request) {
    return resolveGranteeUserId(
        request.getGranteeUserId(),
        request.getGranteeUsername(),
        request.getGranteeEmail());
  }

  private UUID resolveGranteeUserId(AccessRevokeRequest request) {
    return resolveGranteeUserId(
        request.getGranteeUserId(),
        request.getGranteeUsername(),
        request.getGranteeEmail());
  }

  private UUID resolveGranteeUserId(String granteeUserId, String granteeUsername,
      String granteeEmail) {
    int count = 0;
    if (!isBlank(granteeUserId)) {
      count++;
    }
    if (!isBlank(granteeUsername)) {
      count++;
    }
    if (!isBlank(granteeEmail)) {
      count++;
    }
    if (count != 1) {
      throw new IllegalArgumentException(
          "Provide exactly one of granteeUserId, granteeUsername, granteeEmail");
    }
    if (!isBlank(granteeUserId)) {
      try {
        return UUID.fromString(granteeUserId.trim());
      } catch (IllegalArgumentException e) {
        throw new IllegalArgumentException("Invalid granteeUserId UUID", e);
      }
    }
    if (!isBlank(granteeUsername)) {
      return userRepository.findByUsernameIgnoreCase(granteeUsername.trim())
          .orElseThrow(() -> new ResourceNotFoundException(
              "Grantee not found for username: " + granteeUsername.trim()))
          .getId();
    }
    return userRepository.findByEmailIgnoreCase(granteeEmail.trim())
        .orElseThrow(() -> new ResourceNotFoundException(
            "Grantee not found for email: " + granteeEmail.trim()))
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
          .user(userId != null ? new User() {
            {
              setId(userId);
            }
          } : null)
          .document(documentId != null ? new Document() {
            {
              setId(documentId);
            }
          } : null)
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
