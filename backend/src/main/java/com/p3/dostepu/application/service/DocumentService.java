package com.p3.dostepu.application.service;

import java.io.InputStream;
import java.util.Base64;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;
import com.p3.dostepu.api.dto.DocumentUploadRequest;
import com.p3.dostepu.api.dto.DocumentUploadResponse;
import com.p3.dostepu.domain.entity.AccessAction;
import com.p3.dostepu.domain.entity.AccessEventLog;
import com.p3.dostepu.domain.entity.AccessResult;
import com.p3.dostepu.domain.entity.Document;
import com.p3.dostepu.domain.entity.DocumentKeyMetadata;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.repository.AccessEventLogRepository;
import com.p3.dostepu.domain.repository.DocumentKeyMetadataRepository;
import com.p3.dostepu.domain.repository.DocumentRepository;
import com.p3.dostepu.infrastructure.encryption.KmsService;
import com.p3.dostepu.infrastructure.pdf.FastApiPdfClient;
import com.p3.dostepu.infrastructure.storage.StorageService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Updated DocumentService with integrated AuditLogService.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DocumentService {

  private final DocumentRepository documentRepository;
  private final DocumentKeyMetadataRepository keyMetadataRepository;
  private final AccessEventLogRepository auditLogRepository;
  private final StorageService storageService;
  private final FastApiPdfClient fastApiClient;
  private final KmsService kmsService;
  private final AuditLogService auditLogService; // ADD THIS

  /**
   * Upload and encrypt document.
   *
   * @param request document metadata
   * @param pdfFile multipart PDF file
   * @param owner authenticated user (document owner)
   * @param clientIp client IP address for audit
   * @return document upload response
   */
  @Transactional
  public DocumentUploadResponse uploadDocument(DocumentUploadRequest request,
      MultipartFile pdfFile, User owner, String clientIp) {
    UUID documentId = UUID.randomUUID();

    try {
      // Validate input
      if (pdfFile == null || pdfFile.isEmpty()) {
        logAccessEvent(null, null, AccessAction.UPLOAD, AccessResult.FAILURE, clientIp,
            "Missing file");
        throw new IllegalArgumentException("PDF file is required");
      }

      if (pdfFile.getSize() > 104857600) { // 100 MB limit
        logAccessEvent(null, null, AccessAction.UPLOAD, AccessResult.FAILURE, clientIp,
            "File too large");
        throw new IllegalArgumentException("File exceeds 100 MB limit");
      }

      // Step 1: Generate DEK (256-bit for AES-256)
      log.debug("Generating DEK for document: {}", documentId);
      byte[] dek = kmsService.generateDek(documentId);

      // Step 2: Send PDF to FastAPI for encryption with DEK
      log.debug("Sending PDF to FastAPI for AES-256 encryption: {}", documentId);
      String dekBase64 = Base64.getEncoder().encodeToString(dek);
      InputStream encryptedPdfStream = fastApiClient.encryptPdfDocument(documentId,
          pdfFile, dekBase64);

      // Step 3: Store encrypted blob locally or in S3
      log.debug("Storing encrypted PDF blob: {}", documentId);
      String blobPath = storageService.storeEncryptedDocument(documentId,
          pdfFile.getOriginalFilename(), encryptedPdfStream, pdfFile.getSize());

      Long blobSize = storageService.getBlobSize(blobPath);

      // Step 4: Wrap DEK with KMS master key
      log.debug("Wrapping DEK with KMS master key: {}", documentId);
      KmsService.WrappedDekMetadata wrappedMetadata = kmsService.wrapDek(dek,
          documentId);

      // Step 5: Create Document entity
      Document document = Document.builder()
          .id(documentId)
          .owner(owner)
          .title(request.getTitle())
          .description(request.getDescription())
          .tags(request.getTags())
          .blobPath(blobPath)
          .blobSizeBytes(blobSize)
          .encryptedAlgorithm("AES-256-GCM")
          .build();

      document = documentRepository.save(document);
      log.info("Persisted document entity: {}", documentId);

      // Step 6: Create DocumentKeyMetadata with wrapped DEK
      DocumentKeyMetadata keyMetadata = DocumentKeyMetadata.builder()
          .documentId(documentId)
          .wrappedDek(wrappedMetadata.wrappedDek)
          .iv(wrappedMetadata.iv)
          .tag(wrappedMetadata.tag)
          .wrapAlgorithm(wrappedMetadata.algorithm)
          .kmsKeyId(wrappedMetadata.kmsKeyId)
          .kmsKeyVersion(wrappedMetadata.kmsKeyVersion)
          .kmsMetadata(wrappedMetadata.kmsMetadata)
          .build();

      keyMetadataRepository.save(keyMetadata);
      log.info("Persisted key metadata for document: {}", documentId);

      // Step 7: LOG AUDIT EVENT (SUCCESS) - UPDATED
      auditLogService.logUpload(owner.getId(), documentId, blobSize, clientIp, null,
          true, null);

      return DocumentUploadResponse.builder()
          .documentId(documentId)
          .ownerId(owner.getId())
          .createdAt(document.getCreatedAt())
          .status("uploaded")
          .build();

    } catch (Exception e) {
      log.error("Document upload failed: {}", documentId, e);
      // LOG AUDIT EVENT (FAILURE) - UPDATED
      auditLogService.logUpload(owner.getId(), documentId, 0L, clientIp, null, false,
          e.getMessage());
      throw e;
    }
  }

  /**
   * Log access event to audit trail.
   */
  private void logAccessEvent(UUID userId, UUID documentId, AccessAction action,
      AccessResult result, String clientIp, String reason) {
    AccessEventLog event = AccessEventLog.builder()
        .user(userId != null ? new User() { { setId(userId); } } : null)
        .document(
            documentId != null ? new Document() { { setId(documentId); } } : null)
        .action(action)
        .result(result)
        .ipAddress(clientIp)
        .reason(reason)
        .timestampUtc(java.time.ZonedDateTime.now())
        .build();

    auditLogRepository.save(event);
  }
}