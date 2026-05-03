/**
 * Security utilities to prevent PDF download and printing.
 * Per CONTRIBUTING.md: prevent direct file access.
 */

/**
 * Disable browser print function globally in PDF viewer context.
 */
export const disablePrintFunctionality = (): void => {
  // Override window.print (though this may not prevent Ctrl+P)
  const originalPrint = window.print;
  window.print = function () {
    console.warn("Print functionality is disabled for security");
    return undefined;
  };

  // Restore original print function if needed
  if (process.env.NODE_ENV === "development") {
    (window as any).__originalPrint = originalPrint;
  }
};

/**
 * Disable right-click context menu in a specific container.
 */
export const disableContextMenu = (container: HTMLElement | null): void => {
  if (!container) return;

  container.addEventListener("contextmenu", (e: MouseEvent) => {
    e.preventDefault();
    console.warn("Right-click menu is disabled for security");
    return false;
  });
};

/**
 * Disable drag-and-drop (prevent saving PDF via drag).
 */
export const disableDragAndDrop = (container: HTMLElement | null): void => {
  if (!container) return;

  container.addEventListener("dragstart", (e: DragEvent) => {
    e.preventDefault();
    console.warn("Drag-and-drop is disabled for security");
    return false;
  });

  container.addEventListener("drop", (e: DragEvent) => {
    e.preventDefault();
    return false;
  });
};

/**
 * Prevent text selection (discourage copy-paste).
 */
export const disableTextSelection = (container: HTMLElement | null): void => {
  if (!container) return;

  container.style.userSelect = "none";
  container.style.WebkitUserSelect = "none";
  (container.style as any).msUserSelect = "none";
  (container.style as any).MozUserSelect = "none";
};

/**
 * Disable keyboard shortcuts commonly used for saving/printing.
 */
export const disableKeyboardShortcuts = (): void => {
  const disabledKeys = new Set(["s", "p", "q", "i", "j"]);

  document.addEventListener("keydown", (e: KeyboardEvent) => {
    const isCtrlOrCmd = e.ctrlKey || e.metaKey;
    const isAlt = e.altKey;

    if (isCtrlOrCmd && disabledKeys.has(e.key.toLowerCase())) {
      e.preventDefault();
      console.warn(`Keyboard shortcut (${e.key}) is disabled for security`);
      return false;
    }

    // Also disable Alt+S (sometimes used for Save in some browsers)
    if (isAlt && e.key.toLowerCase() === "s") {
      e.preventDefault();
      return false;
    }
  });
};

/**
 * Hide PDF viewer from browser's find-in-page functionality.
 * This prevents users from searching within the PDF via Ctrl+F
 * (Note: This is a UX consideration; full prevention is not possible)
 */
export const warnAboutFind = (): void => {
  document.addEventListener("keydown", (e: KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "f") {
      console.warn(
        "Use the PDF viewer's search functionality instead of browser find"
      );
    }
  });
};

/**
 * Configure canvas element to prevent screenshot/capture.
 * Note: This is advisory only; users with OS-level tools can still capture.
 */
export const configureCanvasForSecurity = (canvas: HTMLCanvasElement): void => {
  // Disable pointer events on canvas (already done in CSS)
  canvas.style.pointerEvents = "none";

  // Warn if user tries to inspect element
  canvas.addEventListener("contextmenu", (e: MouseEvent) => {
    e.preventDefault();
    console.warn("Element inspection is disabled for security");
    return false;
  });
};

/**
 * Apply all security measures to container and canvas.
 */
export const applySecurity = (
  container: HTMLElement | null,
  canvas: HTMLCanvasElement | null
): void => {
  disableContextMenu(container);
  disableDragAndDrop(container);
  disableTextSelection(container);
  disableKeyboardShortcuts();
  disablePrintFunctionality();
  warnAboutFind();

  if (canvas) {
    configureCanvasForSecurity(canvas);
  }
};