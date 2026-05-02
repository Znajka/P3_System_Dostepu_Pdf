package com.p3.dostepu.infrastructure.storage;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;

/**
 * Local filesystem storage implementation. Stores encrypted PDFs in local directory.
 * For production, use S3 or similar cloud storage.
 */
@Slf4j
@Service
@ConditionalOnProperty(name = "storage.type", havingValue = "local",
    matchIfMissing = true)
public class LocalStorageService implements StorageService {

  @Value("${storage.local.path:/data/encrypted-documents}")
  private String storagePath;

  @Override
  public String storeEncryptedDocument(UUID documentId, String fileName,
      InputStream fileData, Long contentLength) {
    try {
      Path dir = Paths.get(storagePath);
      Files.createDirectories(dir);

      String filename = documentId + ".pdf.enc";
      Path filePath = dir.resolve(filename);

      try (FileOutputStream fos = new FileOutputStream(filePath.toFile())) {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = fileData.read(buffer)) != -1) {
          fos.write(buffer, 0, bytesRead);
        }
      }

      log.info("Stored encrypted document: {} at {}", documentId, filePath);
      return filePath.toString();
    } catch (IOException e) {
      log.error("Failed to store encrypted document: {}", documentId, e);
      throw new RuntimeException("Storage error: " + e.getMessage(), e);
    }
  }

  @Override
  public InputStream retrieveEncryptedDocument(String blobPath) {
    try {
      File file = new File(blobPath);
      if (!file.exists()) {
        throw new RuntimeException("Blob not found: " + blobPath);
      }
      return new FileInputStream(file);
    } catch (IOException e) {
      log.error("Failed to retrieve document: {}", blobPath, e);
      throw new RuntimeException("Storage error: " + e.getMessage(), e);
    }
  }

  @Override
  public void deleteDocument(String blobPath) {
    try {
      Files.deleteIfExists(Paths.get(blobPath));
      log.info("Deleted document blob: {}", blobPath);
    } catch (IOException e) {
      log.warn("Failed to delete blob: {}", blobPath, e);
    }
  }

  @Override
  public Long getBlobSize(String blobPath) {
    try {
      return Files.size(Paths.get(blobPath));
    } catch (IOException e) {
      log.error("Failed to get blob size: {}", blobPath, e);
      return 0L;
    }
  }
}