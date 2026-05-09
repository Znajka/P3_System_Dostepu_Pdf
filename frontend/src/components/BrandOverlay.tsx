/**
 * Fixed corner branding on all routes (non-interactive overlay).
 */

import React from "react";

/** Below routed app chrome (see App.tsx z-index wrapper) but above bare page background. */
const overlayBase: React.CSSProperties = {
  pointerEvents: "none",
  position: "fixed",
  zIndex: 1,
};

export const BrandOverlay: React.FC = () => (
  <>
    <img
      src="/logo_png/nazwa.png"
      alt=""
      aria-hidden
      style={{
        ...overlayBase,
        bottom: "max(12px, env(safe-area-inset-bottom, 0px))",
        left: "max(12px, env(safe-area-inset-left, 0px))",
        maxHeight: 56,
        maxWidth: "min(40vw, 320px)",
        width: "auto",
        height: "auto",
        objectFit: "contain",
      }}
    />
    <img
      src="/logo_png/godlo_uwb.svg"
      alt=""
      aria-hidden
      style={{
        ...overlayBase,
        bottom: 12,
        right: 12,
        maxHeight: 88,
        maxWidth: "min(28vw, 200px)",
        width: "auto",
        height: "auto",
        objectFit: "contain",
      }}
    />
  </>
);
