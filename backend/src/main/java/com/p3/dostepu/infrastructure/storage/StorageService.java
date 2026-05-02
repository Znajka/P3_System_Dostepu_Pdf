package com.p3.dostepu.infrastructure.storage;

import java.io.InputStream;
import java.util.UUID;

/**
 * Abstract storage service interface. Implementations: local filesystem, S3, etc.
 */
public interface StorageService {
  /**
   * Upload encrypted document blob. Delegates to FastAPI for encryption.
   *
   * @param documentId unique document identifier
   * @param fileName original file name (for tracing)
   * @param fileData encrypted PDF bytes from FastAPI
   * @param contentLength size in bytes
   * @return path to stored blob (reference only, not direct URL)
   */
  String storeEncryptedDocument(UUID documentId, String fileName, InputStream fileData,
      Long contentLength);

  /**
   * Retrieve encrypted document blob (used by FastAPI for decryption).
   *
   * @param blobPath path reference returned by storeEncryptedDocument
   * @return input stream of encrypted bytes
   */
  InputStream retrieveEncryptedDocument(String blobPath);

  /**
   * Delete document blob (on document soft-delete).
   */
  void deleteDocument(String blobPath);

  /**
   * Get blob size from storage.
   */
  Long getBlobSize(String blobPath);
}