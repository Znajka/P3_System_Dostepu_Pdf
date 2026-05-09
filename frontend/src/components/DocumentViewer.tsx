/**
 * Main document viewer component.
 * Orchestrates ticket retrieval, streaming, and PDF rendering.
 */

import React, { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { apiClient, DocumentStatus } from "../services/api";
import { PdfViewer } from "./PdfViewer";
import { EncryptionMetadata } from "../types";
import type { StreamingError } from "../types";

interface DocumentViewerProps {
  accessToken: string;
}

function fmtIso(iso?: string): string {
  if (!iso) return "";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function accessToolbarSubtitle(access: DocumentStatus["access"], share?: string): string | undefined {
  if (!access) return undefined;
  const st = share || access.shareStatus || "";
  const ends = fmtIso(access.expiresAt);
  const starts = access.validFrom ? fmtIso(access.validFrom) : "";
  if (st === "ACTIVE") {
    return `Your access remains until ${ends}`;
  }
  if (st === "PENDING") {
    return `Access opens ${starts} · ends ${ends}`;
  }
  return undefined;
}

export const DocumentViewer: React.FC<DocumentViewerProps> = ({ accessToken }) => {
  const { documentId } = useParams<{ documentId: string }>();
  const navigate = useNavigate();
  const [docStatus, setDocStatus] = useState<DocumentStatus | null>(null);
  const [pdfData, setPdfData] = useState<ArrayBuffer | null>(null);
  /** Bumps whenever a new decrypted PDF arrives so PdfViewer remounts with fresh password UX. */
  const [pdfLoadRevision, setPdfLoadRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [removingExpired, setRemovingExpired] = useState(false);

  useEffect(() => {
    if (!documentId || !accessToken) {
      setError("Missing document ID or authentication token");
      setLoading(false);
      return;
    }

    const loadDocument = async () => {
      try {
        setLoading(true);
        setError(null);

        console.log(`Fetching document status: ${documentId}`);
        const status = await apiClient.getDocumentStatus(documentId);
        setDocStatus(status);

        if (!status.accessible) {
          if (status.access?.shareStatus && status.access) {
            setLoading(false);
            return;
          }
          setError("You do not have access to this document");
          return;
        }

        console.log("Requesting open-ticket...");
        const ticket = await apiClient.getOpenTicket(documentId);

        console.log("Retrieving encryption metadata...");
        const metadata: EncryptionMetadata = await apiClient.getEncryptionMetadata(documentId);

        console.log("Streaming decrypted PDF from FastAPI...");
        const arrayBuffer = await apiClient.streamDocumentPdf(
          ticket,
          metadata.dek,
          metadata.nonce,
          metadata.tag
        );

        setPdfData(arrayBuffer);
        setPdfLoadRevision((r) => r + 1);
        setError(null);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : "Failed to load document";
        setError(errorMsg);
        console.error("Document loading error:", err);
      } finally {
        setLoading(false);
      }
    };

    loadDocument();
  }, [documentId, accessToken]);

  const handleStreamError = useCallback((streamErr: StreamingError) => {
    setError(streamErr.message);
  }, []);

  /** Re-validates grant with Spring Boot (call before PDF password unlock and on each page/zoom). */
  const verifyDocumentAccess = useCallback(async (): Promise<boolean> => {
    if (!documentId) {
      return false;
    }
    try {
      const s = await apiClient.getDocumentStatus(documentId);
      setDocStatus(s);
      return s.accessible === true;
    } catch {
      return false;
    }
  }, [documentId]);

  const handleDocumentAccessLost = useCallback(() => {
    setPdfData(null);
    setError("You do not have access to this document");
  }, []);

  /**
   * While the PDF is open, re-check grant/access periodically. Pauses when the tab is hidden
   * to save requests; runs again when the tab becomes visible. Transient network errors do not
   * lock the user out (unlike interactive verifyDocumentAccess).
   */
  useEffect(() => {
    if (!documentId || !pdfData || error) {
      return;
    }

    const POLL_MS = 60_000;

    const runPoll = async () => {
      if (typeof document !== "undefined" && document.visibilityState !== "visible") {
        return;
      }
      try {
        const s = await apiClient.getDocumentStatus(documentId);
        setDocStatus(s);
        if (!s.accessible) {
          handleDocumentAccessLost();
        }
      } catch {
        // Ignore network glitches — only explicit accessible=false revokes.
      }
    };

    const intervalId = window.setInterval(runPoll, POLL_MS);

    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        void runPoll();
      }
    };

    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      window.clearInterval(intervalId);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [documentId, pdfData, error, handleDocumentAccessLost]);

  const deleteExpiredGrant = async () => {
    if (
      !documentId ||
      !docStatus?.access?.grantId ||
      docStatus.access.shareStatus !== "EXPIRED"
    ) {
      return;
    }
    setRemovingExpired(true);
    setError(null);
    try {
      await apiClient.deleteGrant(documentId, docStatus.access.grantId);
      navigate("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not remove access record");
    } finally {
      setRemovingExpired(false);
    }
  };

  if (loading) {
    return (
      <div style={{ padding: "20px", textAlign: "center" }}>
        <p>Loading document...</p>
      </div>
    );
  }

  if (
    docStatus &&
    !docStatus.accessible &&
    docStatus.access?.shareStatus &&
    docStatus.access
  ) {
    const a = docStatus.access;
    const st = a.shareStatus || "";
    const badge =
      st === "ACTIVE"
        ? { bg: "#e8f5e9", fg: "#1b5e20", label: "ACTIVE" }
        : st === "PENDING"
          ? { bg: "#fff8e1", fg: "#f57f17", label: "PENDING" }
          : st === "EXPIRED"
            ? { bg: "#ffebee", fg: "#b71c1c", label: "EXPIRED" }
            : { bg: "#f5f5f5", fg: "#424242", label: st };

    return (
      <div style={{ padding: "20px", maxWidth: 560, margin: "0 auto", fontFamily: "system-ui, sans-serif" }}>
        <p style={{ marginBottom: 16 }}>
          <Link to="/dashboard">← Documents</Link>
        </p>
        <div
          style={{
            padding: 20,
            borderRadius: 8,
            background: st === "EXPIRED" ? "#fff3e0" : "#e3f2fd",
            border: `1px solid ${st === "EXPIRED" ? "#ffb74d" : "#90caf9"}`,
            color: "#1a1a1a",
          }}
        >
          <h3 style={{ marginTop: 0 }}>{docStatus.title || "Document"}</h3>
          <p style={{ margin: "8px 0" }}>
            <span
              style={{
                display: "inline-block",
                padding: "2px 10px",
                borderRadius: 999,
                fontWeight: 700,
                fontSize: 12,
                background: badge.bg,
                color: badge.fg,
              }}
            >
              {badge.label}
            </span>
          </p>
          {st === "EXPIRED" && (
            <p style={{ margin: "12px 0" }}>
              Your access to this document ended on{" "}
              <strong>{fmtIso(a.expiresAt)}</strong>.
            </p>
          )}
          {st === "PENDING" && (
            <p style={{ margin: "12px 0" }}>
              Access is scheduled from <strong>{fmtIso(a.validFrom)}</strong> through{" "}
              <strong>{fmtIso(a.expiresAt)}</strong>.
            </p>
          )}
          {st !== "EXPIRED" && st !== "PENDING" && (
            <p style={{ margin: "12px 0", fontSize: 14 }}>
              Valid from <strong>{fmtIso(a.validFrom)}</strong> through{" "}
              <strong>{fmtIso(a.expiresAt)}</strong>.
            </p>
          )}
          {st === "EXPIRED" && a.grantId && (
            <div style={{ marginTop: 16 }}>
              <button
                type="button"
                disabled={removingExpired}
                onClick={deleteExpiredGrant}
                style={{
                  padding: "8px 16px",
                  borderRadius: 6,
                  border: "1px solid #757575",
                  background: removingExpired ? "#eee" : "#fff",
                  cursor: removingExpired ? "not-allowed" : "pointer",
                  fontWeight: 600,
                }}
              >
                {removingExpired ? "Removing…" : "Remove from my list"}
              </button>
            </div>
          )}
          {error && (
            <p style={{ marginTop: 12, color: "#b71c1c", fontSize: 14 }} role="alert">
              {error}
            </p>
          )}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          padding: "20px",
          backgroundColor: "#ffebee",
          border: "1px solid #f48fb1",
          borderRadius: "4px",
          color: "#c2185b",
        }}
      >
        <h3>Error</h3>
        <p>{error}</p>
        <p>
          <Link to="/dashboard">Back to documents</Link>
        </p>
      </div>
    );
  }

  if (!pdfData || !docStatus) {
    return (
      <div style={{ padding: "20px", textAlign: "center" }}>
        <p>No document data</p>
      </div>
    );
  }

  const sub = accessToolbarSubtitle(docStatus.access, docStatus.access?.shareStatus);

  return (
    <PdfViewer
      key={`${documentId}-${pdfLoadRevision}`}
      pdfData={pdfData}
      documentId={documentId!}
      title={docStatus.title}
      subtitle={sub}
      onError={handleStreamError}
      verifyDocumentAccess={verifyDocumentAccess}
      onDocumentAccessLost={handleDocumentAccessLost}
    />
  );
};
