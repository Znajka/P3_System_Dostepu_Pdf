/**
 * PDF.js configuration for secure viewing.
 */

export const PDF_CONFIG = {
  // PDF.js worker source (CDN or local)
  workerSrc: `//cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js`,

  // Maximum file size (100MB)
  maxFileSize: 104857600,

  // Canvas rendering options
  canvasRenderingOptions: {
    alpha: false, // Disable transparency for performance
    willReadFrequently: false,
  },

  // Zoom settings
  zoom: {
    min: 0.5,
    max: 3.0,
    step: 0.25,
    default: 1.0,
  },

  // Streaming settings
  streaming: {
    chunkSize: 65536, // 64KB
    timeout: 120000, // 2 minutes
  },

  // Security settings
  security: {
    disablePrint: true,
    disableDownload: true,
    disableRightClick: true,
    disableKeyboardShortcuts: true,
    disableDragDrop: true,
    disableTextSelection: true,
    hideControls: false, // Show controls but hide print/download
  },

  // Document properties to hide
  hiddenProperties: [
    "filename",
    "filePath",
    "sourceUrl",
  ],
};

export default PDF_CONFIG;