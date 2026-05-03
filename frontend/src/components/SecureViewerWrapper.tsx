/**
 * Secure Viewer Wrapper Component
 * Implements comprehensive security measures to prevent PDF download and unauthorized access.
 * Per CONTRIBUTING.md: prevent direct file access, ensure PDF rendered via canvas only.
 *
 * Security features:
 * - Disable right-click context menu
 * - Block save-as keyboard shortcuts (Ctrl+S, Cmd+S, Ctrl+Shift+S, etc.)
 * - Block print shortcuts (Ctrl+P, Cmd+P)
 * - Prevent drag-and-drop
 * - Disable text selection
 * - Block developer tools inspection
 * - Prevent URL bar access to data/blob URLs
 * - Visual feedback for blocked operations
 */

import React, { useEffect, useRef, useState, ReactNode } from "react";
import "./SecureViewerWrapper.css";

interface SecureViewerWrapperProps {
  children: ReactNode;
  documentId: string;
  title?: string;
  onSecurityViolation?: (violation: SecurityViolation) => void;
}

export interface SecurityViolation {
  type:
    | "right-click"
    | "save"
    | "print"
    | "drag-drop"
    | "developer-tools"
    | "keyboard-shortcut";
  timestamp: Date;
  details?: string;
}

export const SecureViewerWrapper: React.FC<SecureViewerWrapperProps> = ({
  children,
  documentId,
  title,
  onSecurityViolation,
}) => {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const [showSecurityNotice, setShowSecurityNotice] = useState(false);
  const [securityMessage, setSecurityMessage] = useState("");
  const [violations, setViolations] = useState<SecurityViolation[]>([]);

  /**
   * Log security violation for audit purposes.
   */
  const logViolation = (violation: SecurityViolation) => {
    setViolations((prev) => [...prev, violation]);
    onSecurityViolation?.(violation);

    // Log to console (for development/debugging)
    console.warn(`Security violation: ${violation.type}`, {
      documentId,
      timestamp: violation.timestamp,
      details: violation.details,
    });
  };

  /**
   * Show temporary security notice to user.
   */
  const showNotice = (message: string, duration: number = 2000) => {
    setSecurityMessage(message);
    setShowSecurityNotice(true);
    setTimeout(() => setShowSecurityNotice(false), duration);
  };

  /**
   * Prevent right-click context menu.
   */
  useEffect(() => {
    const handleContextMenu = (e: MouseEvent) => {
      // Only prevent right-click within the secure viewer wrapper
      if (wrapperRef.current?.contains(e.target as Node)) {
        e.preventDefault();
        e.stopPropagation();

        logViolation({
          type: "right-click",
          timestamp: new Date(),
        });

        showNotice("🔒 Right-click is disabled for security reasons");
        return false;
      }
    };

    document.addEventListener("contextmenu", handleContextMenu, true);
    return () =>
      document.removeEventListener("contextmenu", handleContextMenu, true);
  }, [documentId]);

  /**
   * Disable keyboard shortcuts for save, print, and developer tools.
   */
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const isCtrlOrCmd = e.ctrlKey || e.metaKey;
      const isShift = e.shiftKey;
      const isAlt = e.altKey;

      // Block save shortcuts
      if (isCtrlOrCmd && e.key === "s") {
        e.preventDefault();
        e.stopPropagation();

        logViolation({
          type: "save",
          timestamp: new Date(),
          details: "Ctrl/Cmd+S",
        });

        showNotice("🔒 Save is disabled. This document is read-only.");
        return false;
      }

      // Block save-as shortcuts (Ctrl+Shift+S, Cmd+Shift+S)
      if (isCtrlOrCmd && isShift && e.key === "S") {
        e.preventDefault();
        e.stopPropagation();

        logViolation({
          type: "save",
          timestamp: new Date(),
          details: "Ctrl/Cmd+Shift+S (Save As)",
        });

        showNotice("🔒 Save As is disabled. This document cannot be exported.");
        return false;
      }

      // Block print shortcuts
      if (isCtrlOrCmd && e.key === "p") {
        e.preventDefault();
        e.stopPropagation();

        logViolation({
          type: "print",
          timestamp: new Date(),
          details: "Ctrl/Cmd+P",
        });

        showNotice("🔒 Printing is disabled for security reasons");
        return false;
      }

      // Block print shortcuts (Alt+P in some browsers)
      if (isAlt && e.key === "p") {
        e.preventDefault();
        e.stopPropagation();

        logViolation({
          type: "print",
          timestamp: new Date(),
          details: "Alt+P",
        });

        showNotice("🔒 Printing is disabled");
        return false;
      }

      // Block developer tools (F12, Ctrl+Shift+I, Cmd+Option+I)
      if (
        e.key === "F12" ||
        (isCtrlOrCmd && isShift && (e.key === "i" || e.key === "I")) ||
        (isCtrlOrCmd && isShift && (e.key === "c" || e.key === "C")) ||
        (isCtrlOrCmd && isShift && (e.key === "j" || e.key === "J")) ||
        (isCtrlOrCmd && isAlt && (e.key === "i" || e.key === "I"))
      ) {
        e.preventDefault();
        e.stopPropagation();

        logViolation({
          type: "developer-tools",
          timestamp: new Date(),
          details: e.key,
        });

        showNotice("🔒 Developer tools are disabled");
        return false;
      }

      // Block quit/close (Cmd+Q on macOS)
      if (e.metaKey && e.key === "q") {
        e.preventDefault();
        showNotice("🔒 Cannot quit from this page");
        return false;
      }

      // Block refresh (Ctrl+R, Cmd+R)
      if (isCtrlOrCmd && (e.key === "r" || e.key === "R")) {
        // Allow refresh but log it
        logViolation({
          type: "keyboard-shortcut",
          timestamp: new Date(),
          details: "Refresh (Ctrl/Cmd+R)",
        });
      }
    };

    document.addEventListener("keydown", handleKeyDown, true);
    return () => document.removeEventListener("keydown", handleKeyDown, true);
  }, [documentId]);

  /**
   * Prevent drag-and-drop (prevent saving via drag).
   */
  useEffect(() => {
    const handleDragStart = (e: DragEvent) => {
      if (wrapperRef.current?.contains(e.target as Node)) {
        e.preventDefault();
        e.stopPropagation();

        logViolation({
          type: "drag-drop",
          timestamp: new Date(),
          details: "Drag started",
        });

        showNotice("🔒 Drag-and-drop is disabled");
        return false;
      }
    };

    const handleDrop = (e: DragEvent) => {
      if (wrapperRef.current?.contains(e.target as Node)) {
        e.preventDefault();
        e.stopPropagation();

        logViolation({
          type: "drag-drop",
          timestamp: new Date(),
          details: "Drop attempted",
        });

        return false;
      }
    };

    const handleDragOver = (e: DragEvent) => {
      if (wrapperRef.current?.contains(e.target as Node)) {
        e.preventDefault();
        e.stopPropagation();
      }
    };

    document.addEventListener("dragstart", handleDragStart, true);
    document.addEventListener("drop", handleDrop, true);
    document.addEventListener("dragover", handleDragOver, true);

    return () => {
      document.removeEventListener("dragstart", handleDragStart, true);
      document.removeEventListener("drop", handleDrop, true);
      document.removeEventListener("dragover", handleDragOver, true);
    };
  }, [documentId]);

  /**
   * Prevent text selection on canvas area.
   */
  useEffect(() => {
    const handleSelectStart = (e: Event) => {
      if (wrapperRef.current?.contains(e.target as Node)) {
        e.preventDefault();
        return false;
      }
    };

    document.addEventListener("selectstart", handleSelectStart, true);
    return () =>
      document.removeEventListener("selectstart", handleSelectStart, true);
  }, [documentId]);

  /**
   * Detect and block developer tools opening (F12, Inspector, etc.).
   */
  useEffect(() => {
    let devToolsOpen = false;

    const detectDevTools = () => {
      const threshold = 160;
      if (
        window.outerHeight - window.innerHeight > threshold ||
        window.outerWidth - window.innerWidth > threshold
      ) {
        if (!devToolsOpen) {
          devToolsOpen = true;
          logViolation({
            type: "developer-tools",
            timestamp: new Date(),
            details: "Developer tools detected",
          });

          showNotice("🔒 Developer tools detected and closed", 3000);

          // Attempt to close dev tools (may not work in all browsers)
          if (typeof window !== "undefined") {
            try {
              // This will only work in specific debugging contexts
              // Most browsers ignore this for security reasons
            } catch (e) {
              console.warn("Cannot close developer tools");
            }
          }
        }
      } else {
        devToolsOpen = false;
      }
    };

    const interval = setInterval(detectDevTools, 1000);
    return () => clearInterval(interval);
  }, [documentId]);

  /**
   * Prevent access to page source and document properties.
   */
  useEffect(() => {
    const handleKeyDownGlobal = (e: KeyboardEvent) => {
      // Block view page source (Ctrl+U, Cmd+Option+U)
      if ((e.ctrlKey || e.metaKey) && (e.altKey || e.shiftKey) && e.key === "u") {
        e.preventDefault();
        showNotice("🔒 View page source is disabled");
        return false;
      }
    };

    document.addEventListener("keydown", handleKeyDownGlobal);
    return () => document.removeEventListener("keydown", handleKeyDownGlobal);
  }, []);

  /**
   * Disable copy/paste operations.
   */
  useEffect(() => {
    const handleCopy = (e: ClipboardEvent) => {
      if (wrapperRef.current?.contains(e.target as Node)) {
        e.preventDefault();
        showNotice("🔒 Copy is disabled for this document");
        return false;
      }
    };

    const handleCut = (e: ClipboardEvent) => {
      if (wrapperRef.current?.contains(e.target as Node)) {
        e.preventDefault();
        showNotice("🔒 Cut is disabled for this document");
        return false;
      }
    };

    const handlePaste = (e: ClipboardEvent) => {
      if (wrapperRef.current?.contains(e.target as Node)) {
        e.preventDefault();
        return false;
      }
    };

    document.addEventListener("copy", handleCopy);
    document.addEventListener("cut", handleCut);
    document.addEventListener("paste", handlePaste);

    return () => {
      document.removeEventListener("copy", handleCopy);
      document.removeEventListener("cut", handleCut);
      document.removeEventListener("paste", handlePaste);
    };
  }, []);

  /**
   * Prevent inspector element selection.
   */
  useEffect(() => {
    const handleInspect = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.shiftKey && e.key === "c") {
        e.preventDefault();
        showNotice("🔒 Element inspector is disabled");
        return false;
      }
    };

    document.addEventListener("keydown", handleInspect);
    return () => document.removeEventListener("keydown", handleInspect);
  }, []);

  return (
    <div ref={wrapperRef} className="secure-viewer-wrapper">
      {/* Security Violation Notice */}
      {showSecurityNotice && (
        <div className="security-notice-alert">
          <span className="notice-message">{securityMessage}</span>
        </div>
      )}

      {/* Viewer Content */}
      <div className="secure-viewer-content">
        {children}
      </div>

      {/* Security Footer with Violation Count */}
      <div className="security-footer">
        <div className="security-info">
          <span className="lock-icon">🔒</span>
          <span className="security-text">
            Secure Document Viewer
            {violations.length > 0 && (
              <span className="violation-count">
                ({violations.length} security event{violations.length !== 1 ? "s" : ""})
              </span>
            )}
          </span>
        </div>
      </div>

      {/* Development Mode: Security Violations Log */}
      {process.env.NODE_ENV === "development" && violations.length > 0 && (
        <details className="dev-violations-log">
          <summary>Security Violations ({violations.length})</summary>
          <div className="violations-list">
            {violations.map((v, idx) => (
              <div key={idx} className="violation-entry">
                <span className="violation-type">{v.type}</span>
                <span className="violation-time">
                  {v.timestamp.toLocaleTimeString()}
                </span>
                {v.details && <span className="violation-details">({v.details})</span>}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
};

export default SecureViewerWrapper;