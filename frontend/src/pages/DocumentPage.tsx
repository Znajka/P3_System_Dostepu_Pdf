/**
 * Document viewing page with secure viewer and audit reporting.
 */

import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { DocumentViewer } from "../components/DocumentViewer";
import SecureViewerWrapper, {
  SecurityViolation,
} from "../components/SecureViewerWrapper";
import { useSecurityAudit } from "../hooks/useSecurityAudit";

interface DocumentPageProps {
  accessToken: string | null;
}

export const DocumentPage: React.FC<DocumentPageProps> = ({ accessToken }) => {
  const navigate = useNavigate();
  const [securityViolations, setSecurityViolations] = useState<
    SecurityViolation[]
  >([]);

  // Extract documentId from URL
  const params = new URLSearchParams(window.location.search);
  const documentId = params.get("documentId") || "doc-123";

  const { reportViolation } = useSecurityAudit(documentId);

  if (!accessToken) {
    return (
      <div style={{ padding: "20px" }}>
        <p>Please log in to view documents.</p>
        <button onClick={() => navigate("/login")}>Go to Login</button>
      </div>
    );
  }

  const handleSecurityViolation = async (violation: SecurityViolation) => {
    setSecurityViolations((prev) => [...prev, violation]);
    await reportViolation(violation);
  };

  return (
    <SecureViewerWrapper
      documentId={documentId}
      title="P3 Dostepu - Secure Document Viewer"
      onSecurityViolation={handleSecurityViolation}
    >
      <DocumentViewer accessToken={accessToken} />
    </SecureViewerWrapper>
  );
};

export default DocumentPage;