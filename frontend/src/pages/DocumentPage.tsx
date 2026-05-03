/**
 * Document viewing page with secure viewer and audit reporting.
 */

import React from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
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
  const { documentId } = useParams<{ documentId: string }>();
  const { reportViolation } = useSecurityAudit(documentId ?? "");

  if (!accessToken) {
    return (
      <div style={{ padding: "20px", fontFamily: "system-ui, sans-serif" }}>
        <p>Please log in to view documents.</p>
        <button type="button" onClick={() => navigate("/login")}>
          Go to login
        </button>
      </div>
    );
  }

  if (!documentId) {
    return (
      <div style={{ padding: 20 }}>
        <p>Missing document id.</p>
        <Link to="/dashboard">Back to documents</Link>
      </div>
    );
  }

  const handleSecurityViolation = async (violation: SecurityViolation) => {
    await reportViolation(violation);
  };

  return (
    <SecureViewerWrapper
      documentId={documentId}
      title="P3 Dostepu — secure viewer"
      onSecurityViolation={handleSecurityViolation}
    >
      <div style={{ margin: "12px 20px", fontFamily: "system-ui, sans-serif" }}>
        <Link to="/dashboard">← Documents</Link>
      </div>
      <DocumentViewer accessToken={accessToken} />
    </SecureViewerWrapper>
  );
};

export default DocumentPage;
