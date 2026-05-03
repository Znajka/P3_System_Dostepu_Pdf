package com.p3.dostepu.integration;

import static org.junit.jupiter.api.Assertions.*;

import java.time.ZonedDateTime;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;
import com.p3.dostepu.application.exception.UnauthorizedException;
import com.p3.dostepu.application.service.AccessGrantService;
import com.p3.dostepu.application.service.DocumentAccessService;
import com.p3.dostepu.api.dto.AccessGrantRequest;
import com.p3.dostepu.api.dto.AccessGrantResponse;
import com.p3.dostepu.api.dto.OpenTicketResponse;
import com.p3.dostepu.domain.entity.Document;
import com.p3.dostepu.domain.entity.DocumentKeyMetadata;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.entity.UserRole;
import com.p3.dostepu.domain.repository.AccessGrantRepository;
import com.p3.dostepu.domain.repository.DocumentKeyMetadataRepository;
import com.p3.dostepu.domain.repository.DocumentRepository;
import com.p3.dostepu.domain.repository.UserRepository;

/**
 * End-to-end test: complete access grant -> ticket fetch workflow.
 * Uses actual service layer (no mocking).
 */
@SpringBootTest
@ActiveProfiles("test")
@DisplayName("E2E: Access Grant and Ticket Workflow")
@Transactional
class E2EAccessGrantTicketTest {

  @Autowired
  private AccessGrantService grantService;

  @Autowired
  private DocumentAccessService accessService;

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

  @BeforeEach
  void setUp() {
    // Create users
    adminUser = createUser("admin", "admin@example.com", Set.of(UserRole.ADMIN));
    ownerUser = createUser("owner", "owner@example.com", Set.of(UserRole.USER));
    authorizedUser = createUser("authorized", "authorized@example.com",
        Set.of(UserRole.USER));
    unauthorizedUser = createUser("unauthorized", "unauthorized@example.com",
        Set.of(UserRole.USER));

    // Create document
    document = createDocument(ownerUser, "E2E Test Document");
  }

  @Test
  @DisplayName("E2E: Admin grants access to user, user fetches ticket successfully")
  void testE2EGrantAndFetchTicket() {
    // Step 1: Admin grants access to authorized user
    AccessGrantRequest grantRequest = AccessGrantRequest.builder()
        .granteeUserId(authorizedUser.getId().toString())
        .expiresAt(ZonedDateTime.now().plusDays(7))
        .note("E2E test grant")
        .build();

    AccessGrantResponse grantResponse = grantService.grantAccess(
        document.getId(), grantRequest, adminUser, "127.0.0.1"
    );

    assertNotNull(grantResponse.getGrantId());
    assertEquals(authorizedUser.getId(), grantResponse.getGranteeUserId());
    assertTrue(grantRepository.findById(grantResponse.getGrantId()).isPresent());

    // Step 2: Authorized user fetches ticket
    OpenTicketResponse ticketResponse = accessService.issueAccessTicket(
        document.getId(), authorizedUser, "127.0.0.1"
    );

    assertNotNull(ticketResponse.getTicket());
    assertNotNull(ticketResponse.getTicketId());
    assertTrue(ticketResponse.getTicket().contains("."));
    assertEquals("pdf-microservice", ticketResponse.getUsage().getAud());

    // Step 3: Unauthorized user cannot fetch ticket
    assertThrows(UnauthorizedException.class, () ->
        accessService.issueAccessTicket(
            document.getId(), unauthorizedUser, "127.0.0.1"
        )
    );
  }

  @Test
  @DisplayName("E2E: Grant expires, user cannot fetch ticket")
  void testE2EExpiredGrantDeniesTicket() throws InterruptedException {
    // Step 1: Grant with short expiration (2 seconds)
    AccessGrantRequest grantRequest = AccessGrantRequest.builder()
        .granteeUserId(authorizedUser.getId().toString())
        .expiresAt(ZonedDateTime.now().plusSeconds(2))
        .build();

    AccessGrantResponse grantResponse = grantService.grantAccess(
        document.getId(), grantRequest, adminUser, "127.0.0.1"
    );

    assertNotNull(grantResponse.getGrantId());

    // Step 2: User can fetch ticket while grant is active
    OpenTicketResponse ticketResponse = accessService.issueAccessTicket(
        document.getId(), authorizedUser, "127.0.0.1"
    );

    assertNotNull(ticketResponse.getTicket());

    // Step 3: Wait for expiration
    Thread.sleep(3000);

    // Step 4: User cannot fetch ticket after expiration
    assertThrows(UnauthorizedException.class, () ->
        accessService.issueAccessTicket(
            document.getId(), authorizedUser, "127.0.0.1"
        )
    );
  }

  @Test
  @DisplayName("E2E: Grant is revoked, user cannot fetch ticket")
  void testE2ERevokedGrantDeniesTicket() {
    // Step 1: Admin grants access
    AccessGrantRequest grantRequest = AccessGrantRequest.builder()
        .granteeUserId(authorizedUser.getId().toString())
        .expiresAt(ZonedDateTime.now().plusDays(7))
        .build();

    AccessGrantResponse grantResponse = grantService.grantAccess(
        document.getId(), grantRequest, adminUser, "127.0.0.1"
    );

    // Step 2: Authorized user can fetch ticket
    OpenTicketResponse ticketResponse = accessService.issueAccessTicket(
        document.getId(), authorizedUser, "127.0.0.1"
    );

    assertNotNull(ticketResponse.getTicket());

    // Step 3: Admin revokes grant
    grantService.revokeAccess(
        document.getId(), authorizedUser.getId(), adminUser, "Testing revocation",
        "127.0.0.1"
    );

    // Step 4: User cannot fetch ticket after revocation
    assertThrows(UnauthorizedException.class, () ->
        accessService.issueAccessTicket(
            document.getId(), authorizedUser, "127.0.0.1"
        )
    );
  }

  @Test
  @DisplayName("E2E: Document owner can view all grants")
  void testE2EOwnerSeesAllGrants() {
    // Step 1: Owner grants access to user 1
    grantService.grantAccess(
        document.getId(),
        AccessGrantRequest.builder()
            .granteeUserId(authorizedUser.getId().toString())
            .expiresAt(ZonedDateTime.now().plusDays(7))
            .build(),
        ownerUser,
        "127.0.0.1"
    );

    // Step 2: Admin grants access to user 2
    grantService.grantAccess(
        document.getId(),
        AccessGrantRequest.builder()
            .granteeUserId(unauthorizedUser.getId().toString())
            .expiresAt(ZonedDateTime.now().plusDays(7))
            .build(),
        adminUser,
        "127.0.0.1"
    );

    // Step 3: Owner queries and verifies both grants exist
    var grants = grantRepository.findByDocumentIdOrderByCreatedAtDesc(document.getId());

    assertEquals(2, grants.size());
    assertTrue(grants.stream()
        .anyMatch(g -> g.getGranteeUser().getId().equals(authorizedUser.getId())));
    assertTrue(grants.stream()
        .anyMatch(g -> g.getGranteeUser().getId().equals(unauthorizedUser.getId())));
  }

  @Test
  @DisplayName("E2E: Multiple authorized users get independent tickets")
  void testE2EMultipleAuthorizedUsersIndependentTickets() {
    // Create additional authorized users
    User user2 = createUser("user2", "user2@example.com", Set.of(UserRole.USER));
    User user3 = createUser("user3", "user3@example.com", Set.of(UserRole.USER));

    // Grant access to all
    for (User user : new User[] { authorizedUser, user2, user3 }) {
      grantService.grantAccess(
          document.getId(),
          AccessGrantRequest.builder()
              .granteeUserId(user.getId().toString())
              .expiresAt(ZonedDateTime.now().plusDays(7))
              .build(),
          adminUser,
          "127.0.0.1"
      );
    }

    // Each user fetches independent ticket
    OpenTicketResponse ticket1 = accessService.issueAccessTicket(
        document.getId(), authorizedUser, "127.0.0.1"
    );
    OpenTicketResponse ticket2 = accessService.issueAccessTicket(
        document.getId(), user2, "127.0.0.1"
    );
    OpenTicketResponse ticket3 = accessService.issueAccessTicket(
        document.getId(), user3, "127.0.0.1"
    );

    // All tickets should be different (different nonces)
    assertNotEquals(ticket1.getTicketId(), ticket2.getTicketId());
    assertNotEquals(ticket2.getTicketId(), ticket3.getTicketId());
    assertNotEquals(ticket1.getTicketId(), ticket3.getTicketId());

    // All tickets should be valid JWTs
    assertTrue(ticket1.getTicket().contains("."));
    assertTrue(ticket2.getTicket().contains("."));
    assertTrue(ticket3.getTicket().contains("."));
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
        .blobPath("/data/test-doc-" + UUID.randomUUID() + ".pdf.enc")
        .blobSizeBytes(1024L)
        .build();

    Document savedDoc = documentRepository.save(doc);

    // Create key metadata
    DocumentKeyMetadata keyMetadata = DocumentKeyMetadata.builder()
        .documentId(savedDoc.getId())
        .wrappedDek("test-wrapped-dek-" + UUID.randomUUID().toString().getBytes())
        .iv("test-iv-".getBytes())
        .tag("test-tag-".getBytes())
        .wrapAlgorithm("AES-KW")
        .kmsKeyId("test-key-id-" + UUID.randomUUID())
        .build();

    keyMetadataRepository.save(keyMetadata);

    return savedDoc;
  }
}