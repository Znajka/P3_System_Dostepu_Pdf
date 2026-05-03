package com.p3.dostepu;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import com.p3.dostepu.security.jwt.JwtProvider;

@SpringBootTest
class IpPinningSecurityTest {

  @Autowired
  private JwtProvider jwtProvider;

  @Test
  void testGenerateTicketWithIpPinning() {
    String ticket = jwtProvider.generateDocumentAccessTicket(
        "user-123",
        "doc-456",
        "nonce-789",
        "192.168.1.100",
        60
    );

    assertNotNull(ticket);
    assertTrue(ticket.contains("."));

    // Extract and verify IP is in token
    String extractedIp = jwtProvider.getIpAddressFromJwt(ticket);
    assertEquals("192.168.1.100", extractedIp);
  }

  @Test
  void testTicketContainsIpPinningEnabled() {
    String ticket = jwtProvider.generateDocumentAccessTicket(
        "user-123",
        "doc-456",
        "nonce-789",
        "192.168.1.100",
        60
    );

    boolean ipPinningEnabled = jwtProvider.isIpPinningEnabledInToken(ticket);
    assertTrue(ipPinningEnabled);
  }

  @Test
  void testExtractIpAddressFromTicket() {
    String ip = "203.0.113.42";
    String ticket = jwtProvider.generateDocumentAccessTicket(
        "user-123",
        "doc-456",
        "nonce-789",
        ip,
        60
    );

    String extractedIp = jwtProvider.getIpAddressFromJwt(ticket);
    assertEquals(ip, extractedIp);
  }
}