/**
 * Main document viewer component.
 * Orchestrates ticket retrieval, streaming, and PDF rendering.
 */

import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { apiClient } from "../services/api";
import { PdfViewer } from "./PdfViewer";
import { Document, StreamingError, EncryptionMetadata } from "../types";

interface DocumentViewerProps {
  accessToken: string;
}

export const DocumentViewer: React.FC<DocumentViewerProps> = ({ accessToken }) => {
  const { documentId } = useParams<{ documentId: string }>();
  const [document, setDocument] = useState<Document | null>(null);
  const [pdfData, setPdfData] = useState<ArrayBuffer | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

        // Step 1: Get document status (to verify access)
        console.log(`Fetching document status: ${documentId}`);
        const docStatus = await apiClient.getDocumentStatus(documentId);
        setDocument(docStatus);

        if (!docStatus.accessible) {
          setError("You do not have access to this document");
          return;
        }

        // Step 2: Request open-ticket from Spring Boot
        console.log("Requesting open-ticket...");
        const ticket = await apiClient.getOpenTicket(documentId);
        console.log("Received ticket (JWT)");

        // Step 3: Get encryption metadata
        console.log("Retrieving encryption metadata...");
        const metadata: EncryptionMetadata = await apiClient.getEncryptionMetadata(
          documentId
        );
        console.log("Received encryption metadata (DEK, nonce, tag)");

        // Step 4: Stream PDF from FastAPI using ticket
        console.log("Streaming decrypted PDF from FastAPI...");
        const arrayBuffer = await apiClient.streamDocumentPdf(
          ticket,
          metadata.dek,
          metadata.nonce,
          metadata.tag
        );
        console.log(`Received PDF: ${arrayBuffer.byteLength} bytes`);

        setPdfData(arrayBuffer);
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

  const handleStreamError = (error: StreamingError) => {
    setError(error.message);
  };

  if (loading) {
    return (
      <div style={{ padding: "20px", textAlign: "center" }}>
        <p>Loading document...</p>
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
      </div>
    );
  }

  if (!pdfData || !document) {
    return (
      <div style={{ padding: "20px", textAlign: "center" }}>
        <p>No document data</p>
      </div>
    );
  }

  return (
    <PdfViewer
      pdfData={pdfData}
      documentId={documentId!}
      title={document.title}
      onError={handleStreamError}
    />
  );
};