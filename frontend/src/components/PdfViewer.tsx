/**
 * PDF Viewer component using PDF.js with enhanced security.
 * Renders PDF to canvas only; prevents download, print, and save operations.
 * Per CONTRIBUTING.md: PDF rendered via PDF.js (canvas), not downloaded.
 */

import React, { useEffect, useRef, useState } from "react";
import * as pdfjsLib from "pdfjs-dist";
import { StreamingError } from "../types";
import { applySecurity } from "../utils/securityUtils";
import "./PdfViewer.css";

// Set PDF.js worker
pdfjsLib.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.js`;

interface PdfViewerProps {
  pdfData: ArrayBuffer;
  documentId: string;
  title?: string;
  onError?: (error: StreamingError) => void;
}

export const PdfViewer: React.FC<PdfViewerProps> = ({
  pdfData,
  documentId,
  title,
  onError,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1.0);
  const [renderingPage, setRenderingPage] = useState(false);
  const pdfDocRef = useRef<pdfjsLib.PDFDocument | null>(null);

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

  // Load and initialize PDF
  useEffect(() => {
    if (!pdfData || pdfData.byteLength === 0) {
      setError("Invalid PDF data");
      onError?.({
        code: "INVALID_PDF",
        message: "PDF data is empty or invalid",
      });
      return;
    }

    const loadPdf = async () => {
      try {
        setLoading(true);

        // Configure PDF.js for security
        pdfjsLib.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjsLib.version}/pdf.worker.min.js`;

        // Load PDF from ArrayBuffer
        const pdf = await pdfjsLib.getDocument({
          data: pdfData,
          useWorkerFetch: false,
          useSystemFonts: true,
          disableAutoFetch: true, // Don't auto-fetch missing pages
          disableStream: true, // Ensure full PDF is loaded (already in memory)
        }).promise;

        pdfDocRef.current = pdf;
        setTotalPages(pdf.numPages);
        setCurrentPage(1);

        // Render first page
        await renderPage(pdf, 1, zoom);

        setError(null);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : "Failed to load PDF";
        setError(errorMsg);
        onError?.({
          code: "PDF_LOAD_ERROR",
          message: errorMsg,
        });
      } finally {
        setLoading(false);
      }
    };

    loadPdf();
  }, [pdfData, onError]);

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
      onError?.({
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
    if (currentPage > 1 && pdfDocRef.current && !renderingPage) {
      const newPage = currentPage - 1;
      await renderPage(pdfDocRef.current, newPage, zoom);
      setCurrentPage(newPage);
    }
  };

  /**
   * Navigate to next page.
   */
  const handleNextPage = async () => {
    if (currentPage < totalPages && pdfDocRef.current && !renderingPage) {
      const newPage = currentPage + 1;
      await renderPage(pdfDocRef.current, newPage, zoom);
      setCurrentPage(newPage);
    }
  };

  /**
   * Jump to specific page.
   */
  const handleGoToPage = async (page: number) => {
    const validPage = Math.min(Math.max(1, page), totalPages);
    if (validPage !== currentPage && pdfDocRef.current && !renderingPage) {
      await renderPage(pdfDocRef.current, validPage, zoom);
      setCurrentPage(validPage);
    }
  };

  /**
   * Zoom in.
   */
  const handleZoomIn = async () => {
    if (pdfDocRef.current && !renderingPage) {
      const newZoom = Math.min(zoom + 0.25, 3.0);
      setZoom(newZoom);
      await renderPage(pdfDocRef.current, currentPage, newZoom);
    }
  };

  /**
   * Zoom out.
   */
  const handleZoomOut = async () => {
    if (pdfDocRef.current && !renderingPage) {
      const newZoom = Math.max(zoom - 0.25, 0.5);
      setZoom(newZoom);
      await renderPage(pdfDocRef.current, currentPage, newZoom);
    }
  };

  /**
   * Reset zoom to 100%.
   */
  const handleResetZoom = async () => {
    if (pdfDocRef.current && !renderingPage && zoom !== 1.0) {
      setZoom(1.0);
      await renderPage(pdfDocRef.current, currentPage, 1.0);
    }
  };

  return (
    <div className="pdf-viewer-container" ref={containerRef}>
      {/* Header Toolbar */}
      <div className="pdf-toolbar">
        <div className="toolbar-section">
          <h3 className="document-title">
            {title || `Document: ${documentId}`}
          </h3>
        </div>

        <div className="toolbar-section">
          <span className="page-info">
            Page {currentPage} of {totalPages}
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

      {/* PDF Canvas Area */}
      <div className="pdf-canvas-container">
        {loading ? (
          <div className="loading-overlay">
            <div className="spinner" />
            <p>Loading PDF...</p>
          </div>
        ) : error ? (
          <div className="error-overlay">
            <h3>Error Loading PDF</h3>
            <p>{error}</p>
          </div>
        ) : (
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
  );
};

export default PdfViewer;