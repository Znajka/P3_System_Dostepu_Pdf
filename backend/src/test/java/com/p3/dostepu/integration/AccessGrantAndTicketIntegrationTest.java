package com.p3.dostepu.integration;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.time.ZonedDateTime;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.p3.dostepu.domain.entity.Document;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.entity.UserRole;
import com.p3.dostepu.domain.repository.DocumentRepository;
import com.p3.dostepu.domain.repository.UserRepository;
import com.p3.dostepu.domain.repository.AccessGrantRepository;
import com.p3.dostepu.domain.repository.DocumentKeyMetadataRepository;
import com.p3.dostepu.domain.entity.DocumentKeyMetadata;

/**
 * Integration test suite for access grant and ticket workflow.
 * Per CONTRIBUTING.md: verify ADMIN can grant access and USER can fetch tickets.
 * 
 * Test scenarios:
 * 1. ADMIN grants access to USER -> USER can fetch ticket
 * 2. Non-authorized USER cannot fetch ticket
 * 3. Expired grant -> USER cannot fetch ticket
 * 4. Revoked grant -> USER cannot fetch ticket
 * 5. Rate limiting on failed ticket attempts
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DisplayName("Access Grant and Ticket Workflow Integration Tests")
@Transactional
class AccessGrantAndTicketIntegrationTest {

  @Autowired
  private MockMvc mockMvc;

  @Autowired
  private ObjectMapper objectMapper;

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private DocumentRepository documentRepository;

  @Autowired
  private AccessGrantRepository grantRepository;

  @Autowired
  private DocumentKeyMetadataRepository keyMetadataRepository;

  private User adminUser;
  private User ownerUser;
  private User authorizedUser;
  private User unauthorizedUser;
  private Document document;
  private String adminToken;
  private String ownerToken;
  private String authorizedUserToken;
  private String unauthorizedUserToken;

  @BeforeEach
  void setUp() {
    // Create test users
    adminUser = createUser("admin", "admin@example.com", Set.of(UserRole.ADMIN));
    ownerUser = createUser("owner", "owner@example.com", Set.of(UserRole.USER));
    authorizedUser = createUser("authorized-user", "authorized@example.com",
        Set.of(UserRole.USER));
    unauthorizedUser = createUser("unauthorized-user", "unauthorized@example.com",
        Set.of(UserRole.USER));

    // Create test document owned by OWNER
    document = createDocument(ownerUser, "Test Document for Grant Flow");

    // Generate tokens (mock authentication for testing)
    adminToken = generateMockToken(adminUser.getId(), "ADMIN");
    ownerToken = generateMockToken(ownerUser.getId(), "USER");
    authorizedUserToken = generateMockToken(authorizedUser.getId(), "USER");
    unauthorizedUserToken = generateMockToken(unauthorizedUser.getId(), "USER");
  }

  /**
   * Test suite: Admin grants access to authorized user.
   */
  @Nested
  @DisplayName("Admin Grants Access")
  class AdminGrantsAccessTests {

    @Test
    @DisplayName("ADMIN successfully grants access to USER")
    void testAdminGrantsAccessToUser() throws Exception {
      // Arrange
      String grantRequestJson = objectMapper.writeValueAsString(
          new AccessGrantRequestDto(
              authorizedUser.getId().toString(),
              ZonedDateTime.now().plusDays(7),
              "Access for review"
          )
      );

      // Act: ADMIN grants access
      MvcResult grantResult = mockMvc
          .perform(post("/api/documents/{id}/grant", document.getId())
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(grantRequestJson))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.grantId").exists())
          .andExpect(jsonPath("$.documentId").value(document.getId().toString()))
          .andExpect(jsonPath("$.granteeUserId").value(authorizedUser.getId().toString()))
          .andReturn();

      // Assert: Grant created successfully
      String responseBody = grantResult.getResponse().getContentAsString();
      JsonNode responseJson = objectMapper.readTree(responseBody);
      UUID grantId = UUID.fromString(responseJson.get("grantId").asText());

      assertNotNull(grantId);
      assertTrue(grantRepository.findById(grantId).isPresent());
    }

    @Test
    @DisplayName("OWNER successfully grants access to USER")
    void testOwnerGrantsAccessToUser() throws Exception {
      // Arrange
      String grantRequestJson = objectMapper.writeValueAsString(
          new AccessGrantRequestDto(
              authorizedUser.getId().toString(),
              ZonedDateTime.now().plusDays(7),
              null
          )
      );

      // Act: OWNER grants access
      MvcResult grantResult = mockMvc
          .perform(post("/api/documents/{id}/grant", document.getId())
              .header("Authorization", "Bearer " + ownerToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(grantRequestJson))
          .andExpect(status().isOk())
          .andReturn();

      // Assert
      String responseBody = grantResult.getResponse().getContentAsString();
      JsonNode responseJson = objectMapper.readTree(responseBody);
      assertNotNull(responseJson.get("grantId"));
    }

    @Test
    @DisplayName("Non-owner USER cannot grant access on others documents")
    void testUnauthorizedUserCannotGrantAccess() throws Exception {
      // Arrange
      String grantRequestJson = objectMapper.writeValueAsString(
          new AccessGrantRequestDto(
              authorizedUser.getId().toString(),
              ZonedDateTime.now().plusDays(7),
              null
          )
      );

      // Act & Assert: Unauthorized user denied
      mockMvc
          .perform(post("/api/documents/{id}/grant", document.getId())
              .header("Authorization", "Bearer " + unauthorizedUserToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(grantRequestJson))
          .andExpect(status().isForbidden());
    }
  }

  /**
   * Test suite: Authorized user fetches ticket after grant.
   */
  @Nested
  @DisplayName("Authorized User Fetches Ticket")
  class AuthorizedUserTicketFetchTests {

    @BeforeEach
    void setUpGrant() throws Exception {
      // Grant access to authorized user
      String grantRequestJson = objectMapper.writeValueAsString(
          new AccessGrantRequestDto(
              authorizedUser.getId().toString(),
              ZonedDateTime.now().plusDays(7),
              null
          )
      );

      mockMvc
          .perform(post("/api/documents/{id}/grant", document.getId())
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(grantRequestJson))
          .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Authorized USER successfully fetches ticket")
    void testAuthorizedUserFetchesTicket() throws Exception {
      // Act: Authorized user requests ticket
      MvcResult ticketResult = mockMvc
          .perform(get("/api/documents/{id}/open-ticket", document.getId())
              .header("Authorization", "Bearer " + authorizedUserToken))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.ticket").exists())
          .andExpect(jsonPath("$.ticketId").exists())
          .andExpect(jsonPath("$.expiresAt").exists())
          .andExpect(jsonPath("$.usage.singleUse").value(true))
          .andExpect(jsonPath("$.usage.aud").value("pdf-microservice"))
          .andExpect(jsonPath("$.usage.documentId").value(document.getId().toString()))
          .andReturn();

      // Assert: Ticket contains all required fields
      String responseBody = ticketResult.getResponse().getContentAsString();
      JsonNode responseJson = objectMapper.readTree(responseBody);

      assertNotNull(responseJson.get("ticket").asText());
      assertNotNull(responseJson.get("ticketId").asText());
      assertTrue(responseJson.get("ticket").asText().contains("."));
    }

    @Test
    @DisplayName("Ticket is valid JWT")
    void testTicketIsValidJwt() throws Exception {
      // Act: Fetch ticket
      MvcResult ticketResult = mockMvc
          .perform(get("/api/documents/{id}/open-ticket", document.getId())
              .header("Authorization", "Bearer " + authorizedUserToken))
          .andExpect(status().isOk())
          .andReturn();

      String responseBody = ticketResult.getResponse().getContentAsString();
      JsonNode responseJson = objectMapper.readTree(responseBody);
      String ticket = responseJson.get("ticket").asText();

      // Assert: JWT format (3 parts separated by dots)
      String[] parts = ticket.split("\\.");
      assertEquals(3, parts.length, "JWT should have 3 parts (header.payload.signature)");
    }

    @Test
    @DisplayName("Document status shows access for authorized USER")
    void testDocumentStatusShowsAuthorizedAccess() throws Exception {
      // Act: Fetch document status
      MvcResult statusResult = mockMvc
          .perform(get("/api/documents/{id}/status", document.getId())
              .header("Authorization", "Bearer " + authorizedUserToken))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.documentId").value(document.getId().toString()))
          .andExpect(jsonPath("$.accessible").value(true))
          .andExpect(jsonPath("$.access.expiresAt").exists())
          .andReturn();

      // Assert
      String responseBody = statusResult.getResponse().getContentAsString();
      JsonNode responseJson = objectMapper.readTree(responseBody);
      assertTrue(responseJson.get("accessible").asBoolean());
    }
  }

  /**
   * Test suite: Unauthorized user cannot fetch ticket.
   */
  @Nested
  @DisplayName("Unauthorized User Cannot Fetch Ticket")
  class UnauthorizedUserTicketFetchTests {

    @BeforeEach
    void setUpGrant() throws Exception {
      // Grant access only to authorized user
      String grantRequestJson = objectMapper.writeValueAsString(
          new AccessGrantRequestDto(
              authorizedUser.getId().toString(),
              ZonedDateTime.now().plusDays(7),
              null
          )
      );

      mockMvc
          .perform(post("/api/documents/{id}/grant", document.getId())
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(grantRequestJson))
          .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Unauthorized USER cannot fetch ticket")
    void testUnauthorizedUserCannotFetchTicket() throws Exception {
      // Act & Assert: Unauthorized user denied
      mockMvc
          .perform(get("/api/documents/{id}/open-ticket", document.getId())
              .header("Authorization", "Bearer " + unauthorizedUserToken))
          .andExpect(status().isForbidden())
          .andExpect(jsonPath("$.error.code").value("FORBIDDEN"));
    }

    @Test
    @DisplayName("Unauthorized USER sees no access in document status")
    void testUnauthorizedUserSeeNoAccess() throws Exception {
      // Act: Fetch document status
      MvcResult statusResult = mockMvc
          .perform(get("/api/documents/{id}/status", document.getId())
              .header("Authorization", "Bearer " + unauthorizedUserToken))
          .andExpect(status().isOk())
          .andReturn();

      // Assert: No access indicated
      String responseBody = statusResult.getResponse().getContentAsString();
      JsonNode responseJson = objectMapper.readTree(responseBody);
      assertFalse(responseJson.get("accessible").asBoolean());
    }

    @Test
    @DisplayName("User without grant cannot see grant details")
    void testUnauthorizedUserSeeNoGrantDetails() throws Exception {
      // Act: Fetch document status
      MvcResult statusResult = mockMvc
          .perform(get("/api/documents/{id}/status", document.getId())
              .header("Authorization", "Bearer " + unauthorizedUserToken))
          .andExpect(status().isOk())
          .andReturn();

      // Assert: Access field should not contain grant details
      String responseBody = statusResult.getResponse().getContentAsString();
      JsonNode responseJson = objectMapper.readTree(responseBody);
      assertNull(responseJson.get("access"));
    }
  }

  /**
   * Test suite: Expired grant denies access.
   */
  @Nested
  @DisplayName("Expired Grant Scenarios")
  class ExpiredGrantTests {

    @BeforeEach
    void setUpExpiredGrant() throws Exception {
      // Grant access with expiration in the past
      String grantRequestJson = objectMapper.writeValueAsString(
          new AccessGrantRequestDto(
              authorizedUser.getId().toString(),
              ZonedDateTime.now().minusMinutes(1), // Expired
              null
          )
      );

      // Admin cannot grant with past expiration, so we manipulate the grant directly
      // (in real scenario, expiration would happen during the grant window)
      // For this test, we'll use the scheduled expiration task to handle it
    }

    @Test
    @DisplayName("USER cannot fetch ticket for expired grant")
    void testExpiredGrantDeniesTicketFetch() throws Exception {
      // Arrange: Grant access with future expiration
      String grantRequestJson = objectMapper.writeValueAsString(
          new AccessGrantRequestDto(
              authorizedUser.getId().toString(),
              ZonedDateTime.now().plusSeconds(2), // Expires in 2 seconds
              null
          )
      );

      mockMvc
          .perform(post("/api/documents/{id}/grant", document.getId())
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(grantRequestJson))
          .andExpect(status().isOk());

      // Wait for expiration
      Thread.sleep(3000);

      // Act & Assert: Expired grant denies access
      mockMvc
          .perform(get("/api/documents/{id}/open-ticket", document.getId())
              .header("Authorization", "Bearer " + authorizedUserToken))
          .andExpect(status().isForbidden());
    }
  }

  /**
   * Test suite: Revoked grant denies access.
   */
  @Nested
  @DisplayName("Revoked Grant Scenarios")
  class RevokedGrantTests {

    @BeforeEach
    void setUpAndRevokeGrant() throws Exception {
      // Grant access
      String grantRequestJson = objectMapper.writeValueAsString(
          new AccessGrantRequestDto(
              authorizedUser.getId().toString(),
              ZonedDateTime.now().plusDays(7),
              null
          )
      );

      MvcResult grantResult = mockMvc
          .perform(post("/api/documents/{id}/grant", document.getId())
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(grantRequestJson))
          .andExpect(status().isOk())
          .andReturn();

      // Revoke the grant
      String revokeRequestJson = objectMapper.writeValueAsString(
          new AccessRevokeRequestDto(authorizedUser.getId().toString(), "Testing revocation")
      );

      mockMvc
          .perform(post("/api/documents/{id}/revoke", document.getId())
              .header("Authorization", "Bearer " + adminToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(revokeRequestJson))
          .andExpect(status().isOk());
    }

    @Test
    @DisplayName("USER cannot fetch ticket after grant is revoked")
    void testRevokedGrantDeniesTicketFetch() throws Exception {
      // Act & Assert: Revoked grant denies access
      mockMvc
          .perform(get("/api/documents/{id}/open-ticket", document.getId())
              .header("Authorization", "Bearer " + authorizedUserToken))
          .andExpect(status().isForbidden())
          .andExpect(jsonPath("$.error.message").containsString("No valid grant"));
    }
  }

  /**
   * Test suite: Owner can view all grants.
   */
  @Nested
  @DisplayName("Owner Views Grants")
  class OwnerViewsGrantsTests {

    @BeforeEach
    void setUpMultipleGrants() throws Exception {
      // Grant to user 1
      mockMvc
          .perform(post("/api/documents/{id}/grant", document.getId())
              .header("Authorization", "Bearer " + ownerToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(
                  new AccessGrantRequestDto(
                      authorizedUser.getId().toString(),
                      ZonedDateTime.now().plusDays(7),
                      null
                  )
              )))
          .andExpect(status().isOk());

      // Grant to user 2
      mockMvc
          .perform(post("/api/documents/{id}/grant", document.getId())
              .header("Authorization", "Bearer " + ownerToken)
              .contentType(MediaType.APPLICATION_JSON)
              .content(objectMapper.writeValueAsString(
                  new AccessGrantRequestDto(
                      unauthorizedUser.getId().toString(),
                      ZonedDateTime.now().plusDays(7),
                      null
                  )
              )))
          .andExpect(status().isOk());
    }

    @Test
    @DisplayName("OWNER sees all grants in document status")
    void testOwnerSeesAllGrants() throws Exception {
      // Act: Owner fetches document status
      MvcResult statusResult = mockMvc
          .perform(get("/api/documents/{id}/status", document.getId())
              .header("Authorization", "Bearer " + ownerToken))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.grants").isArray())
          .andReturn();

      // Assert: Both grants visible
      String responseBody = statusResult.getResponse().getContentAsString();
      JsonNode responseJson = objectMapper.readTree(responseBody);
      assertTrue(responseJson.get("grants").size() >= 2);
    }
  }

  /**
   * Test suite: Rate limiting on failed ticket attempts.
   */
  @Nested
  @DisplayName("Rate Limiting on Failed Ticket Attempts")
  class RateLimitingTests {

    @Test
    @DisplayName("Multiple failed ticket attempts trigger rate limit")
    void testFailedAttemptsTriggersRateLimit() throws Exception {
      // Act & Assert: Make 5 failed attempts
      for (int i = 0; i < 5; i++) {
        mockMvc
            .perform(get("/api/documents/{id}/open-ticket", document.getId())
                .header("Authorization", "Bearer " + unauthorizedUserToken))
            .andExpect(status().isForbidden());
      }

      // 6th attempt should be rate limited
      mockMvc
          .perform(get("/api/documents/{id}/open-ticket", document.getId())
              .header("Authorization", "Bearer " + unauthorizedUserToken))
          .andExpect(status().isTooManyRequests())
          .andExpect(header().exists("Retry-After"));
    }
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================

  private User createUser(String username, String email, Set<UserRole> roles) {
    User user = User.builder()
        .username(username)
        .email(email)
        .passwordHash("hashed-password")
        .roles(roles)
        .failedAttempts(0)
        .active(true)
        .build();

    return userRepository.save(user);
  }

  private Document createDocument(User owner, String title) {
    Document doc = Document.builder()
        .owner(owner)
        .title(title)
        .blobPath("/data/test-doc.pdf.enc")
        .blobSizeBytes(1024L)
        .build();

    Document savedDoc = documentRepository.save(doc);

    // Create key metadata
    DocumentKeyMetadata keyMetadata = DocumentKeyMetadata.builder()
        .documentId(savedDoc.getId())
        .wrappedDek("test-wrapped-dek".getBytes())
        .iv("test-iv".getBytes())
        .tag("test-tag".getBytes())
        .wrapAlgorithm("AES-KW")
        .kmsKeyId("test-key-id")
        .build();

    keyMetadataRepository.save(keyMetadata);

    return savedDoc;
  }

  private String generateMockToken(UUID userId, String role) {
    // In real tests, use @WithMockUser or generate actual JWT
    // This is a placeholder for testing purposes
    return "mock-token-" + userId + "-" + role;
  }

  // ============================================================================
  // DTOs for testing
  // ============================================================================

  public static class AccessGrantRequestDto {
    public String granteeUserId;
    public ZonedDateTime expiresAt;
    public String note;

    public AccessGrantRequestDto(String granteeUserId, ZonedDateTime expiresAt,
        String note) {
      this.granteeUserId = granteeUserId;
      this.expiresAt = expiresAt;
      this.note = note;
    }
  }

  public static class AccessRevokeRequestDto {
    public String granteeUserId;
    public String reason;

    public AccessRevokeRequestDto(String granteeUserId, String reason) {
      this.granteeUserId = granteeUserId;
      this.reason = reason;
    }
  }
}