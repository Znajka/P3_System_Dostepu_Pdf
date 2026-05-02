package com.p3.dostepu.infrastructure.pdf;

import java.io.InputStream;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.DefaultSslBundleRegistry;
import org.springframework.boot.ssl.SslBundle;
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
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * FastAPI PDF client: internal service-to-service communication.
 * Calls POST /api/internal/encrypt to upload PDF for encryption.
 * Uses mTLS for secure communication.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class FastApiPdfClient {

  private final RestTemplate restTemplate;
  private final ObjectMapper objectMapper;

  @Value("${fastapi.service.url:https://fastapi-pdf-service:8443}")
  private String fastApiUrl;

  /**
   * Send PDF to FastAPI /internal/encrypt endpoint for encryption.
   * Spring Boot generates DEK, sends PDF + DEK -> FastAPI encrypts and saves.
   *
   * @param documentId document UUID
   * @param pdfFile multipart PDF file
   * @param dekBase64 Base64-encoded 32-byte DEK
   * @return EncryptionResponse with nonce, tag, blob path
   */
  public EncryptionResponse encryptPdfDocument(UUID documentId, MultipartFile pdfFile,
      String dekBase64) {
    try {
      String url = fastApiUrl + "/api/internal/encrypt";

      MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
      body.add("document_id", documentId.toString());
      body.add("dek_base64", dekBase64);
      body.add("file", new ByteArrayResource(pdfFile.getBytes()) {
        @Override
        public String getFilename() {
          return pdfFile.getOriginalFilename();
        }
      });

      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.MULTIPART_FORM_DATA);
      headers.set("X-Service-ID", "spring-boot-backend"); // Service authentication
      HttpEntity<MultiValueMap<String, Object>> request = new HttpEntity<>(body, headers);

      log.info("Sending PDF to FastAPI for encryption: {} (size: {} bytes)", documentId,
          pdfFile.getSize());

      ResponseEntity<String> response = restTemplate.postForEntity(url, request,
          String.class);

      if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
        JsonNode responseJson = objectMapper.readTree(response.getBody());

        EncryptionResponse encResponse = EncryptionResponse.builder()
            .documentId(responseJson.get("document_id").asText())
            .status(responseJson.get("status").asText())
            .blobPath(responseJson.get("blob_path").asText())
            .nonce(responseJson.get("nonce").asText())
            .tag(responseJson.get("tag").asText())
            .ciphertextSize(responseJson.get("ciphertext_size").asLong())
            .algorithm(responseJson.get("algorithm").asText())
            .build();

        log.info(
            "Received encryption response from FastAPI: {} (blob: {}, ciphertext: {} bytes)",
            documentId, encResponse.getBlobPath(), encResponse.getCiphertextSize());

        return encResponse;
      } else {
        log.error("FastAPI encryption failed: {} (status {})", documentId,
            response.getStatusCode());
        throw new RuntimeException(
            "FastAPI encryption failed: " + response.getStatusCode());
      }

    } catch (RestClientException e) {
      log.error("FastAPI communication error: {}", e.getMessage(), e);
      throw new RuntimeException("Encryption service unavailable", e);
    } catch (Exception e) {
      log.error("Failed to encrypt PDF: {}", e.getMessage(), e);
      throw new RuntimeException("Encryption failed", e);
    }
  }

  /**
   * DTO for FastAPI encryption response.
   */
  @lombok.Getter
  @lombok.Setter
  @lombok.AllArgsConstructor
  @lombok.Builder
  public static class EncryptionResponse {
    private String documentId;
    private String status;
    private String blobPath;
    private String nonce;
    private String tag;
    private Long ciphertextSize;
    private String algorithm;
  }
}