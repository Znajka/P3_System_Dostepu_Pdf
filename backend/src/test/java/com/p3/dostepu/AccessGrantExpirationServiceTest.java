package com.p3.dostepu;

import static org.junit.jupiter.api.Assertions.*;

import java.time.ZonedDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import com.p3.dostepu.application.service.AccessGrantExpirationService;
import com.p3.dostepu.domain.entity.AccessGrant;
import com.p3.dostepu.domain.entity.Document;
import com.p3.dostepu.domain.entity.User;
import com.p3.dostepu.domain.entity.UserRole;
import com.p3.dostepu.domain.repository.AccessGrantRepository;
import com.p3.dostepu.domain.repository.DocumentRepository;
import com.p3.dostepu.domain.repository.UserRepository;

@SpringBootTest
@ActiveProfiles("test")
class AccessGrantExpirationServiceTest {

  @Autowired
  private AccessGrantExpirationService expirationService;

  @Autowired
  private AccessGrantRepository grantRepository;

  @Autowired
  private DocumentRepository documentRepository;

  @Autowired
  private UserRepository userRepository;

  private User owner;
  private User grantee;
  private Document document;

  @BeforeEach
  void setUp() {
    // Create test users
    owner = User.builder()
        .username("owner")
        .email("owner@example.com")
        .passwordHash("hashed")
        .roles(java.util.Set.of(UserRole.OWNER))
        .active(true)
        .build();
    owner = userRepository.save(owner);

    grantee = User.builder()
        .username("grantee")
        .email("grantee@example.com")
        .passwordHash("hashed")
        .roles(java.util.Set.of(UserRole.USER))
        .active(true)
        .build();
    grantee = userRepository.save(grantee);

    // Create test document
    document = Document.builder()
        .owner(owner)
        .title("Test Document")
        .blobPath("/data/doc.enc")
        .blobSizeBytes(1024L)
        .build();
    document = documentRepository.save(document);
  }

  @Test
  void testRevokeExpiredGrants() {
    // Create expired grant
    AccessGrant expiredGrant = AccessGrant.builder()
        .document(document)
        .granteeUser(grantee)
        .grantedByUser(owner)
        .expiresAt(ZonedDateTime.now().minusHours(1)) // Expired
        .revoked(false)
        .build();
    expiredGrant = grantRepository.save(expiredGrant);

    // Run expiration task
    expirationService.revokeExpiredGrants();

    // Verify grant is revoked
    AccessGrant revokedGrant = grantRepository.findById(expiredGrant.getId()).orElseThrow();
    assertTrue(revokedGrant.getRevoked());
    assertNotNull(revokedGrant.getRevokedAt());
    assertEquals("Automatic expiration", revokedGrant.getRevokeReason());
  }

  @Test
  void testDoNotRevokeValidGrants() {
    // Create valid (not expired) grant
    AccessGrant validGrant = AccessGrant.builder()
        .document(document)
        .granteeUser(grantee)
        .grantedByUser(owner)
        .expiresAt(ZonedDateTime.now().plusHours(1)) // Not expired
        .revoked(false)
        .build();
    validGrant = grantRepository.save(validGrant);

    // Run expiration task
    expirationService.revokeExpiredGrants();

    // Verify grant is NOT revoked
    AccessGrant result = grantRepository.findById(validGrant.getId()).orElseThrow();
    assertFalse(result.getRevoked());
  }

  @Test
  void testDoNotRevokeAlreadyRevoked() {
    // Create already revoked grant
    AccessGrant revokedGrant = AccessGrant.builder()
        .document(document)
        .granteeUser(grantee)
        .grantedByUser(owner)
        .expiresAt(ZonedDateTime.now().minusHours(1))
        .revoked(true) // Already revoked
        .revokedAt(ZonedDateTime.now().minusHours(2))
        .build();
    revokedGrant = grantRepository.save(revokedGrant);

    // Run expiration task
    expirationService.revokeExpiredGrants();

    // Verify grant remains unchanged
    AccessGrant result = grantRepository.findById(revokedGrant.getId()).orElseThrow();
    assertEquals(revokedGrant.getRevokedAt(), result.getRevokedAt());
  }

  @Test
  void testRevokeMultipleExpiredGrants() {
    // Create multiple expired grants
    for (int i = 0; i < 3; i++) {
      AccessGrant grant = AccessGrant.builder()
          .document(document)
          .granteeUser(grantee)
          .grantedByUser(owner)
          .expiresAt(ZonedDateTime.now().minusMinutes(i))
          .revoked(false)
          .build();
      grantRepository.save(grant);
    }

    // Verify all grants are not revoked initially
    long countBefore = grantRepository.countExpiredGrants(ZonedDateTime.now());
    assertEquals(3, countBefore);

    // Run expiration task
    expirationService.revokeExpiredGrants();

    // Verify all grants are revoked
    long countAfter = grantRepository.countExpiredGrants(ZonedDateTime.now());
    assertEquals(0, countAfter);
  }

  @Test
  void testTaskStats() {
    // Create expired grant
    AccessGrant grant = AccessGrant.builder()
        .document(document)
        .granteeUser(grantee)
        .grantedByUser(owner)
        .expiresAt(ZonedDateTime.now().minusHours(1))
        .revoked(false)
        .build();
    grantRepository.save(grant);

    // Run task
    expirationService.revokeExpiredGrants();

    // Get stats
    AccessGrantExpirationService.GrantExpirationStats stats = expirationService.getStats();

    assertNotNull(stats);
    assertTrue(stats.getEnabled());
    assertEquals(1, stats.getLastRevokedCount());
    assertTrue(stats.getLastExecutionTimeMs() > 0);
  }
}