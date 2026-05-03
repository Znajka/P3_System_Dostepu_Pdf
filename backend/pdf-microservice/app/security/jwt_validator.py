"""
JWT validation utility for FastAPI with IP-pinning support.
Per CONTRIBUTING.md API Design: JWT with expiration and revocation.
Enhanced: validates IP address pinning for ticket security.
"""

import logging
import os
import re
from typing import Optional, Dict, Any
from datetime import datetime
import jwt
from jwt import PyJWTError

logger = logging.getLogger(__name__)


class JwtValidator:
    """
    Validates JWT tokens issued by Spring Boot with IP-pinning support.
    - Algorithms: HS256 (Spring default) and HS512 (legacy tests)
    - Claims: sub (user_id), doc (document_id), aud (pdf-microservice),
      jti (ticket_id), ip (client IP), exp (expiration), iat (issued_at)
    """

    # Regex patterns for IP validation
    IPV4_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )

    IPV6_PATTERN = re.compile(
        r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    )

    def __init__(self, secret_key: str = None):
        """
        Initialize JWT validator.

        Args:
            secret_key: JWT secret (shared between Spring Boot and FastAPI).
                       If None, loads from environment variable APP_JWT_SECRET.
        """
        self.secret_key = secret_key or os.getenv(
            "APP_JWT_SECRET", "change-me-in-production"
        )
        self.algorithms = ["HS256", "HS512"]
        self.ip_pinning_enabled = os.getenv("APP_SECURITY_IP_PINNING_ENABLED", "true").lower() == "true"

        if not self.secret_key or self.secret_key == "change-me-in-production":
            logger.warning(
                "JWT secret not properly configured. Use APP_JWT_SECRET "
                "environment variable."
            )

    def validate_open_ticket_with_ip_pinning(
        self,
        token: str,
        expected_document_id: str,
        expected_user_id: str,
        client_ip: str
    ) -> Dict[str, Any]:
        """
        Validate open-ticket JWT with IP-pinning check.

        Args:
            token: JWT token string
            expected_document_id: document ID to validate against
            expected_user_id: user ID to validate against
            client_ip: client IP address (from request)

        Returns:
            Dictionary of validated claims

        Raises:
            ValueError: if validation fails
            jwt.InvalidTokenError: if token is invalid
        """
        try:
            # Step 1: Validate token signature and expiration
            payload = self._validate_token(token)

            # Step 2: Validate required claims
            required_claims = ["sub", "doc", "aud", "jti", "exp", "iat"]
            for claim in required_claims:
                if claim not in payload:
                    raise ValueError(f"Missing required claim: {claim}")

            # Step 3: Validate audience
            if payload.get("aud") != "pdf-microservice":
                raise ValueError(
                    f"Invalid audience: {payload.get('aud')}, expected 'pdf-microservice'"
                )

            # Step 4: Validate document ID
            token_doc_id = payload.get("doc")
            if token_doc_id != expected_document_id:
                logger.warning(
                    "Document ID mismatch: expected=%s, got=%s",
                    expected_document_id, token_doc_id
                )
                raise ValueError("Document ID mismatch")

            # Step 5: Validate user ID
            token_user_id = payload.get("sub")
            if token_user_id != expected_user_id:
                logger.warning(
                    "User ID mismatch: expected=%s, got=%s",
                    expected_user_id, token_user_id
                )
                raise ValueError("User ID mismatch")

            # Step 6: Validate IP pinning (critical security check)
            self._validate_ip_pinning(payload, client_ip)

            logger.info(
                "Open-ticket validated successfully: user=%s, doc=%s, clientIp=%s",
                token_user_id, token_doc_id, client_ip
            )

            return payload

        except (ValueError, jwt.InvalidTokenError) as e:
            logger.error("Open-ticket validation failed: %s", str(e))
            raise

    def validate_open_ticket(
        self,
        token: str,
        expected_document_id: Optional[str] = None,
        expected_user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate streaming ticket claims (signature + aud + required claims).
        Does not enforce IP pinning (use validate_stream_ticket from the edge).
        """
        payload = self._validate_token(token)
        required_claims = ["sub", "doc", "aud", "jti", "exp", "iat"]
        for claim in required_claims:
            if claim not in payload:
                raise ValueError(f"Missing required claim: {claim}")
        if payload.get("aud") != "pdf-microservice":
            raise ValueError("Invalid audience")
        if expected_document_id is not None and payload.get(
            "doc"
        ) != expected_document_id:
            raise ValueError("Document ID mismatch")
        if expected_user_id is not None and payload.get(
            "sub"
        ) != expected_user_id:
            raise ValueError("User ID mismatch")
        return payload

    def validate_stream_ticket(self, token: str, client_ip: str) -> Dict[str, Any]:
        """Validate ticket for browser streaming (includes IP pinning when enabled)."""
        payload = self.validate_open_ticket(token)
        self._validate_ip_pinning(payload, client_ip or "")
        return payload

    def extract_user_id(self, token: str) -> str:
        payload = self._validate_token(token)
        sub = payload.get("sub")
        if not sub:
            raise ValueError("Missing sub claim")
        return str(sub)

    def extract_jti(self, token: str) -> str:
        payload = self._validate_token(token)
        jti = payload.get("jti")
        if not jti:
            raise ValueError("Missing jti claim")
        return str(jti)

    def _validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT token and extract claims.

        Raises:
            jwt.InvalidTokenError: if token is invalid
        """
        try:
            payload = jwt.decode(
                token, self.secret_key, algorithms=self.algorithms
            )
            logger.debug("Token validated successfully for user: %s", payload.get("sub"))
            return payload

        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            raise

        except jwt.InvalidTokenError as e:
            logger.warning("Invalid token: %s", str(e))
            raise

    def _validate_ip_pinning(self, claims: Dict[str, Any], client_ip: str) -> None:
        """
        Validate IP address pinning.
        Ensures ticket was requested from same IP and is being used from same IP.

        Args:
            claims: JWT claims dictionary
            client_ip: client IP address from request

        Raises:
            ValueError: if IP mismatch detected
        """
        # Check if IP pinning is enabled
        ip_pinning_enabled = claims.get("ip_pinning_enabled", False)

        if not ip_pinning_enabled:
            logger.debug("IP pinning not enabled for this ticket")
            return

        # Extract pinned IP from token
        pinned_ip = claims.get("ip")

        if not pinned_ip:
            logger.warning("IP pinning enabled but no IP found in token")
            raise ValueError("IP pinning violation: no pinned IP in token")

        # Validate current client IP format
        if not self._is_valid_ip_address(client_ip):
            logger.warning("Invalid client IP format: %s", client_ip)
            raise ValueError("Invalid IP address format")

        # Validate pinned IP format
        if not self._is_valid_ip_address(pinned_ip):
            logger.error("Invalid pinned IP format in token: %s", pinned_ip)
            raise ValueError("Invalid pinned IP format in token")

        # Compare IPs
        if not self._ip_addresses_match(pinned_ip, client_ip):
            logger.warning(
                "IP mismatch (possible token theft or proxy): pinnedIp=%s, clientIp=%s",
                self._mask_ip_address(pinned_ip),
                self._mask_ip_address(client_ip)
            )
            raise ValueError(
                f"IP mismatch: ticket pinned to {self._mask_ip_address(pinned_ip)}, "
                f"current IP is {self._mask_ip_address(client_ip)}"
            )

        logger.debug("IP pinning validation passed: ip=%s", self._mask_ip_address(client_ip))

    def _ip_addresses_match(self, ip1: str, ip2: str) -> bool:
        """Check if two IP addresses match (handles IPv4/IPv6)."""
        # Exact match
        if ip1 == ip2:
            return True

        # Handle IPv4-mapped IPv6 addresses
        normalized_ip1 = self._normalize_ip_address(ip1)
        normalized_ip2 = self._normalize_ip_address(ip2)

        return normalized_ip1 == normalized_ip2

    def _normalize_ip_address(self, ip: str) -> str:
        """Normalize IP address for comparison."""
        if not ip:
            return ""

        # Remove IPv4-mapped IPv6 prefix
        if ip.startswith("::ffff:"):
            return ip[7:]

        return ip

    def _is_valid_ip_address(self, ip: str) -> bool:
        """Validate IP address format (IPv4 or IPv6)."""
        if not ip:
            return False

        # Check IPv4 format
        if self.IPV4_PATTERN.match(ip):
            return True

        # Check IPv6 format
        if self.IPV6_PATTERN.match(ip):
            return True

        # Check IPv6 with compression (simplified)
        if ":" in ip:
            return True

        return False

    @staticmethod
    def _mask_ip_address(ip: str) -> str:
        """
        Mask IP address for logging (hide last octet for privacy).
        Example: 192.168.1.100 -> 192.168.1.*
        """
        if not ip:
            return "unknown"

        if ":" in ip:
            # IPv6: hide last segment
            last_colon = ip.rfind(":")
            return ip[:last_colon] + ":****"
        else:
            # IPv4: hide last octet
            last_dot = ip.rfind(".")
            if last_dot > 0:
                return ip[:last_dot] + ".*"

        return ip