/**
 * Hook for tracking and reporting security violations to backend.
 */

import { useCallback } from "react";
import { SecurityViolation } from "../components/SecureViewerWrapper";

interface SecurityAuditEvent {
  documentId: string;
  violationType: string;
  details?: string;
  timestamp: string;
  userAgent: string;
}

export const useSecurityAudit = (documentId: string) => {
  /**
   * Report security violation to Spring Boot audit log.
   */
  const reportViolation = useCallback(
    async (violation: SecurityViolation) => {
      try {
        const event: SecurityAuditEvent = {
          documentId,
          violationType: violation.type,
          details: violation.details,
          timestamp: violation.timestamp.toISOString(),
          userAgent: navigator.userAgent,
        };

        // TODO: Send to Spring Boot audit endpoint
        // await fetch("/api/internal/audit/security-violation", {
        //   method: "POST",
        //   headers: {
        //     "Content-Type": "application/json",
        //     "Authorization": `Bearer ${accessToken}`,
        //   },
        //   body: JSON.stringify(event),
        // });

        if (process.env.NODE_ENV === "development") {
          console.debug("Security violation logged:", event);
        }
      } catch (error) {
        console.error("Failed to report security violation:", error);
      }
    },
    [documentId]
  );

  return { reportViolation };
};