/**
 * PDF Viewer component using PDF.js with enhanced security.
 * Renders PDF to canvas only; prevents download, print, and save operations.
 * Per CONTRIBUTING.md: PDF rendered via PDF.js (canvas), not downloaded.
 */

import React, { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import * as pdfjsLib from "pdfjs-dist";
import { StreamingError } from "../types";
import { applySecurity } from "../utils/securityUtils";
import "./PdfViewer.css";

// Set PDF.js worker
pdfjsLib.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.js`;

/** PDF.js PasswordResponses (stable across 3.x) */
const PDF_PASSWORD_NEED = 1;
const PDF_PASSWORD_INCORRECT = 2;

/**
 * Collect messages from PDF.js / worker errors (often wrapped; name may be lost).
 */
function passwordErrorTexts(err: unknown): string {
  const parts: string[] = [];
  const walk = (e: unknown, depth: number) => {
    if (depth > 5 || e == null) return;
    if (typeof e === "string") {
      parts.push(e);
      return;
    }
    if (typeof e !== "object") return;
    const o = e as Record<string, unknown>;
    if (typeof o.message === "string") parts.push(o.message);
    if (typeof o.name === "string") parts.push(o.name);
    if (typeof o.details === "string") parts.push(o.details);
    if (typeof o.str === "string") parts.push(o.str);
    if (o.cause != null) walk(o.cause, depth + 1);
  };
  walk(err, 0);
  return parts.join(" ").toLowerCase();
}

/**
 * Detect PDF.js encryption password errors thrown from getDocument (.promise).
 * Worker/bundler combinations may drop PasswordException.name but keep "No password given".
 */
function classifyPdfPasswordError(err: unknown): "need" | "wrong" | null {
  if (err == null) return null;

  const e = typeof err === "object" ? (err as Record<string, unknown>) : null;
  const name =
    e && typeof e.name === "string" ? e.name.toLowerCase() : "";
  const code = e && typeof e.code === "number" ? e.code : undefined;

  if (name === "passwordexception") {
    return code === PDF_PASSWORD_INCORRECT ? "wrong" : "need";
  }
  if (code === PDF_PASSWORD_INCORRECT) return "wrong";
  if (code === PDF_PASSWORD_NEED) return "need";

  const blob = passwordErrorTexts(err);

  if (
    blob.includes("incorrect password") ||
    blob.includes("wrong password") ||
    blob.includes("invalid password")
  ) {
    return "wrong";
  }
  if (
    blob.includes("no password given") ||
    blob.includes("password required") ||
    blob.includes("need password") ||
    blob.includes("password needed") ||
    blob.includes("encrypted") && blob.includes("password")
  ) {
    return "need";
  }
  return null;
}

interface PdfViewerProps {
  pdfData: ArrayBuffer;
  documentId: string;
  title?: string;
  /** Shown below the title (e.g. access expiry for grantees). */
  subtitle?: string;
  onError?: (error: StreamingError) => void;
  /**
   * Called before PDF password unlock and before page/zoom changes. Must return true only if
   * the user still has server-side access (e.g. grant valid). If false, viewer clears and parent locks out.
   */
  verifyDocumentAccess?: () => Promise<boolean>;
  /** Parent sets global “no access” state (clears PDF buffer, shows message). */
  onDocumentAccessLost?: () => void;
}

export const PdfViewer: React.FC<PdfViewerProps> = ({
  pdfData,
  documentId,
  title,
  subtitle,
  onError,
  verifyDocumentAccess,
  onDocumentAccessLost,
}) => {
  /** Keep latest handler without re-running PDF load effect (parent re-renders after status polling/checks). */
  const onErrorRef = useRef(onError);
  onErrorRef.current = onError;

  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1.0);
  const [renderingPage, setRenderingPage] = useState(false);
  const pdfDocRef = useRef<pdfjsLib.PDFDocument | null>(null);
  /**
   * PDF.js may transfer/detach ArrayBuffers passed to getDocument(); the parent's prop can
   * become empty on retry. Keep an immutable snapshot and pass a fresh slice each load.
   */
  const masterPdfBufferRef = useRef<ArrayBuffer | null>(null);

  useLayoutEffect(() => {
    if (!pdfData || pdfData.byteLength === 0) {
      masterPdfBufferRef.current = null;
      return;
    }
    masterPdfBufferRef.current = pdfData.slice(0);
  }, [pdfData]);

  /** null = do not pass `password` to PDF.js (first attempt); string = user's PDF password attempt */
  const [pdfOwnerPassword, setPdfOwnerPassword] = useState<string | null>(null);
  const [needPasswordPrompt, setNeedPasswordPrompt] = useState(false);
  const [passwordDraft, setPasswordDraft] = useState("");
  const [passwordGateError, setPasswordGateError] = useState<string | null>(
    null
  );
  const [accessVerifying, setAccessVerifying] = useState(false);

  // Disable right-click context menu (prevent save-as)
  useEffect(() => {
    const handleContextMenu = (e: MouseEvent) => {
      if (containerRef.current?.contains(e.target as Node)) {
        e.preventDefault();
        return false;
      }
    };

    document.addEventListener("contextmenu", handleContextMenu);
    return () => document.removeEventListener("contextmenu", handleContextMenu);
  }, []);

  // Disable keyboard shortcuts (Ctrl+S, Ctrl+P, Cmd+S, Cmd+P)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const isCtrlOrCmd = e.ctrlKey || e.metaKey;

      // Disable save (Ctrl/Cmd + S)
      if (isCtrlOrCmd && e.key === "s") {
        e.preventDefault();
        console.warn("Save operation disabled for security");
        return false;
      }

      // Disable print (Ctrl/Cmd + P)
      if (isCtrlOrCmd && e.key === "p") {
        e.preventDefault();
        console.warn("Print operation disabled for security");
        return false;
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Load and initialize PDF (may require owner/user password for encrypted PDFs)
  useEffect(() => {
    const master = masterPdfBufferRef.current;
    if (!master || master.byteLength === 0) {
      setError("Invalid PDF data");
      onErrorRef.current?.({
        code: "INVALID_PDF",
        message: "PDF data is empty or invalid",
      });
      return;
    }

    let cancelled = false;

    const loadPdf = async () => {
      if (cancelled) return;

      try {
        setLoading(true);
        setError(null);
        pdfjsLib.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.js`;

        if (pdfDocRef.current) {
          await pdfDocRef.current.destroy().catch(() => undefined);
          pdfDocRef.current = null;
        }

        /** New ArrayBuffer each attempt so PDF.js cannot leave us with a detached buffer. */
        const dataSlice = master.slice(0);

        const baseOpts = {
          data: dataSlice,
          useWorkerFetch: false as const,
          useSystemFonts: true,
          disableAutoFetch: true,
          disableStream: true,
        };
        const loadArgs =
          pdfOwnerPassword !== null
            ? { ...baseOpts, password: pdfOwnerPassword }
            : baseOpts;

        const pdf = await pdfjsLib.getDocument(loadArgs).promise;
        if (cancelled) {
          await pdf.destroy().catch(() => undefined);
          return;
        }

        pdfDocRef.current = pdf;
        setNeedPasswordPrompt(false);
        setPasswordGateError(null);
        setTotalPages(pdf.numPages);
        setCurrentPage(1);
        await renderPage(pdf, 1, zoom);
        setError(null);
      } catch (err) {
        if (cancelled) return;

        const kind = classifyPdfPasswordError(err);
        if (kind === "need" && pdfOwnerPassword === null) {
          setNeedPasswordPrompt(true);
          setPasswordGateError(null);
          setError(null);
          return;
        }
        if (
          kind === "wrong" ||
          (kind === "need" && pdfOwnerPassword !== null)
        ) {
          setNeedPasswordPrompt(true);
          setPasswordGateError(
            kind === "wrong"
              ? "Incorrect password. Try again."
              : "A password is still required."
          );
          setError(null);
          return;
        }

        const errorMsg =
          err instanceof Error ? err.message : "Failed to load PDF";
        setError(errorMsg);
        setNeedPasswordPrompt(false);
        onErrorRef.current?.({
          code: "PDF_LOAD_ERROR",
          message: errorMsg,
        });
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void loadPdf();

    return () => {
      cancelled = true;
      const d = pdfDocRef.current;
      pdfDocRef.current = null;
      void d?.destroy();
    };
    // Intentionally omit onError: stable via onErrorRef so parent re-renders (e.g. setDocStatus on access check)
    // do not destroy and reload PDF.js — that caused "transport destroyed" on page change.
  }, [pdfData, pdfOwnerPassword]);

  /**
   * Re-check grant/access with Spring Boot before continuing (password unlock or navigation).
   */
  const ensureDocumentAccess = async (): Promise<boolean> => {
    if (!verifyDocumentAccess) {
      return true;
    }
    try {
      const ok = await verifyDocumentAccess();
      if (!ok) {
        const d = pdfDocRef.current;
        pdfDocRef.current = null;
        await d?.destroy().catch(() => undefined);
        setTotalPages(0);
        setCurrentPage(1);
        setNeedPasswordPrompt(false);
        setLoading(false);
        setZoom(1);
        onDocumentAccessLost?.();
      }
      return ok;
    } catch {
      const d = pdfDocRef.current;
      pdfDocRef.current = null;
      await d?.destroy().catch(() => undefined);
      setTotalPages(0);
      setCurrentPage(1);
      setNeedPasswordPrompt(false);
      setLoading(false);
      onDocumentAccessLost?.();
      return false;
    }
  };

  const handlePdfPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordGateError(null);
    setAccessVerifying(true);
    try {
      const ok = await ensureDocumentAccess();
      if (!ok) {
        return;
      }
      setPdfOwnerPassword(passwordDraft);
    } finally {
      setAccessVerifying(false);
    }
  };

  // Apply security restrictions after component is mounted
  useEffect(() => {
    if (containerRef.current && canvasRef.current) {
      applySecurity(containerRef.current, canvasRef.current);
    }
  }, []);

  /**
   * Render a specific page to canvas.
   * Uses PDF.js canvas renderer (not embeddable PDF).
   */
  const renderPage = async (
    pdf: pdfjsLib.PDFDocument,
    pageNumber: number,
    scale: number = 1.0
  ) => {
    try {
      if (!canvasRef.current) return;

      setRenderingPage(true);

      const page = await pdf.getPage(pageNumber);
      const viewport = page.getViewport({ scale });

      // Set canvas dimensions
      canvasRef.current.width = viewport.width;
      canvasRef.current.height = viewport.height;

      const canvasContext = canvasRef.current.getContext("2d", {
        alpha: false, // Disable transparency for performance
      });

      if (!canvasContext) {
        throw new Error("Failed to get canvas context");
      }

      const renderContext: pdfjsLib.RenderParameters = {
        canvasContext,
        viewport,
      };

      // Render page to canvas
      await page.render(renderContext).promise;

      setRenderingPage(false);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : "Failed to render page";
      setError(errorMsg);
      onErrorRef.current?.({
        code: "RENDER_ERROR",
        message: errorMsg,
      });
      setRenderingPage(false);
    }
  };

  /**
   * Navigate to previous page.
   */
  const handlePreviousPage = async () => {
    if (currentPage <= 1 || !pdfDocRef.current || renderingPage) {
      return;
    }
    const ok = await ensureDocumentAccess();
    if (!ok) {
      return;
    }
    const newPage = currentPage - 1;
    await renderPage(pdfDocRef.current, newPage, zoom);
    setCurrentPage(newPage);
  };

  /**
   * Navigate to next page.
   */
  const handleNextPage = async () => {
    if (currentPage >= totalPages || !pdfDocRef.current || renderingPage) {
      return;
    }
    const ok = await ensureDocumentAccess();
    if (!ok) {
      return;
    }
    const newPage = currentPage + 1;
    await renderPage(pdfDocRef.current, newPage, zoom);
    setCurrentPage(newPage);
  };

  /**
   * Jump to specific page.
   */
  const handleGoToPage = async (page: number) => {
    const validPage = Math.min(Math.max(1, page), totalPages);
    if (validPage === currentPage || !pdfDocRef.current || renderingPage) {
      return;
    }
    const ok = await ensureDocumentAccess();
    if (!ok) {
      return;
    }
    await renderPage(pdfDocRef.current, validPage, zoom);
    setCurrentPage(validPage);
  };

  /**
   * Zoom in.
   */
  const handleZoomIn = async () => {
    if (!pdfDocRef.current || renderingPage) {
      return;
    }
    const ok = await ensureDocumentAccess();
    if (!ok) {
      return;
    }
    const newZoom = Math.min(zoom + 0.25, 3.0);
    setZoom(newZoom);
    await renderPage(pdfDocRef.current, currentPage, newZoom);
  };

  /**
   * Zoom out.
   */
  const handleZoomOut = async () => {
    if (!pdfDocRef.current || renderingPage) {
      return;
    }
    const ok = await ensureDocumentAccess();
    if (!ok) {
      return;
    }
    const newZoom = Math.max(zoom - 0.25, 0.5);
    setZoom(newZoom);
    await renderPage(pdfDocRef.current, currentPage, newZoom);
  };

  /**
   * Reset zoom to 100%.
   */
  const handleResetZoom = async () => {
    if (!pdfDocRef.current || renderingPage || zoom === 1.0) {
      return;
    }
    const ok = await ensureDocumentAccess();
    if (!ok) {
      return;
    }
    setZoom(1.0);
    await renderPage(pdfDocRef.current, currentPage, 1.0);
  };

  const passwordPortal =
    typeof document !== "undefined" && needPasswordPrompt && !loading
      ? createPortal(
          <div
            className="pdf-password-overlay-fixed"
            role="dialog"
            aria-modal="true"
            aria-labelledby="pdf-pw-title"
          >
            <form className="pdf-password-dialog" onSubmit={handlePdfPasswordSubmit}>
              <h3 id="pdf-pw-title">Password-protected PDF</h3>
              <p>
                This file was encrypted in Acrobat or another PDF tool. Enter its
                opening password to view it.{" "}
                <strong>The password is verified only on your device</strong> — it is
                never sent to the server.
              </p>
              <label htmlFor="pdf-open-password">Document password</label>
              <input
                id="pdf-open-password"
                type="password"
                autoComplete="off"
                value={passwordDraft}
                onChange={(ev) => setPasswordDraft(ev.target.value)}
                disabled={loading || accessVerifying}
                aria-invalid={passwordGateError ? true : undefined}
              />
              {passwordGateError && (
                <p className="pdf-password-hint" role="alert">
                  {passwordGateError}
                </p>
              )}
              {!passwordGateError && (
                <p className="pdf-password-hint pdf-password-hint--info">
                  Tip: Owner-only restrictions without a user password cannot be unlocked
                  from the viewer — re-export the PDF without encryption if needed.
                </p>
              )}
              <div className="pdf-password-actions">
                <button type="submit" disabled={loading || accessVerifying}>
                  {accessVerifying
                    ? "Checking access…"
                    : loading
                      ? "Unlocking…"
                      : "Unlock and view"}
                </button>
              </div>
            </form>
          </div>,
          document.body
        )
      : null;

  return (
    <>
      {passwordPortal}
      <div className="pdf-viewer-container" ref={containerRef}>
      {/* Header Toolbar */}
      <div className="pdf-toolbar">
        <div className="toolbar-section">
          <div>
            <h3 className="document-title">
              {title || `Document: ${documentId}`}
            </h3>
            {subtitle && (
              <div className="document-access-hint" style={{ fontSize: 12, opacity: 0.95, marginTop: 4 }}>
                {subtitle}
              </div>
            )}
          </div>
        </div>

        <div className="toolbar-section">
          <span className="page-info">
            {totalPages > 0
              ? `Page ${currentPage} of ${totalPages}`
              : "Enter password or wait…"}
          </span>
        </div>

        <div className="toolbar-controls">
          {/* Navigation */}
          <button
            onClick={handlePreviousPage}
            disabled={currentPage <= 1 || loading || renderingPage}
            className="toolbar-btn"
            title="Previous page (Alt+Left)"
            aria-label="Previous page"
          >
            ◀ Prev
          </button>

          <input
            type="number"
            min={1}
            max={totalPages}
            value={currentPage}
            onChange={(e) => {
              const page = parseInt(e.target.value) || 1;
              handleGoToPage(page);
            }}
            disabled={loading || renderingPage}
            className="page-input"
            aria-label="Go to page"
          />

          <button
            onClick={handleNextPage}
            disabled={currentPage >= totalPages || loading || renderingPage}
            className="toolbar-btn"
            title="Next page (Alt+Right)"
            aria-label="Next page"
          >
            Next ▶
          </button>

          <div className="toolbar-divider" />

          {/* Zoom Controls */}
          <button
            onClick={handleZoomOut}
            disabled={zoom <= 0.5 || loading || renderingPage}
            className="toolbar-btn"
            title="Zoom out (Ctrl+Minus)"
            aria-label="Zoom out"
          >
            🔍−
          </button>

          <span className="zoom-level">{Math.round(zoom * 100)}%</span>

          <button
            onClick={handleZoomIn}
            disabled={zoom >= 3.0 || loading || renderingPage}
            className="toolbar-btn"
            title="Zoom in (Ctrl+Plus)"
            aria-label="Zoom in"
          >
            🔍+
          </button>

          <button
            onClick={handleResetZoom}
            disabled={loading || renderingPage}
            className="toolbar-btn"
            title="Reset zoom to 100%"
            aria-label="Reset zoom"
          >
            ↺ 100%
          </button>
        </div>
      </div>

      {/* PDF Canvas Area — keep canvas mounted while loading so first-page render has a real ref */}
      <div className="pdf-canvas-container">
        {error ? (
          <div className="error-overlay">
            <h3>Error Loading PDF</h3>
            <p>{error}</p>
          </div>
        ) : (
          <>
            <div className="canvas-wrapper">
              <canvas
                ref={canvasRef}
                className="pdf-canvas"
                onContextMenu={(e) => e.preventDefault()}
              />
              {renderingPage && (
                <div className="rendering-overlay">
                  <span>Rendering...</span>
                </div>
              )}
            </div>
            {loading && (
              <div className="loading-overlay loading-overlay--on-canvas" aria-busy="true">
                <div className="spinner" />
                <p>
                  {needPasswordPrompt && pdfOwnerPassword !== null
                    ? "Trying password…"
                    : "Loading PDF..."}
                </p>
              </div>
            )}
          </>
        )}
      </div>

      {/* Footer Security Notice */}
      <div className="pdf-footer">
        <div className="security-notice">
          🔒 <strong>Encrypted & Secure:</strong> This document cannot be downloaded,
          printed, or saved. View only via this secure viewer.
        </div>
      </div>
    </div>
    </>
  );
};

export default PdfViewer;