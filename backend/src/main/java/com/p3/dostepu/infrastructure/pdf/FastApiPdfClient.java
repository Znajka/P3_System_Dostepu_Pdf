package com.p3.dostepu.infrastructure.pdf;

import java.io.InputStream;
import java.util.UUID;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * FastAPI PDF microservice client. Sends PDF for encryption, retrieves encrypted blob.
 * Uses mTLS for service-to-service communication.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class FastApiPdfClient {

  private final RestTemplate restTemplate;

  /**
   * Send PDF to FastAPI for AES-256 encryption. FastAPI returns encrypted blob.
   *
   * @param documentId document identifier
   * @param pdfFile multipart PDF file
   * @param dekBase64 Base64-encoded DEK for FastAPI to use
   * @return encrypted PDF bytes
   */
  public InputStream encryptPdfDocument(UUID documentId, MultipartFile pdfFile,
      String dekBase64) {
    try {
      String fastApiUrl = "https://fastapi-pdf-service:8443/api/encrypt";

      MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
      body.add("file", new ByteArrayResource(pdfFile.getBytes()) {
        @Override
        public String getFilename() {
          return pdfFile.getOriginalFilename();
        }
      });
      body.add("document_id", documentId.toString());
      body.add("dek", dekBase64);

      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.MULTIPART_FORM_DATA);
      HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);

      log.info("Sending PDF to FastAPI for encryption: {}", documentId);
      ResponseEntity<byte[]> response = restTemplate.postForEntity(fastApiUrl, request,
          byte[].class);

      if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
        log.info("Received encrypted PDF from FastAPI: {} bytes", response.getBody().length);
        return new java.io.ByteArrayInputStream(response.getBody());
      } else {
        throw new RuntimeException("FastAPI encryption failed: " + response.getStatusCode());
      }
    } catch (RestClientException e) {
      log.error("FastAPI communication error: {}", e.getMessage(), e);
      throw new RuntimeException("Encryption service unavailable", e);
    } catch (Exception e) {
      log.error("Failed to encrypt PDF: {}", e.getMessage(), e);
      throw new RuntimeException("Encryption failed", e);
    }
  }
}