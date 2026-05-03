/**
 * Vite configuration for React frontend.
 */

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    minify: "esbuild",
  },
  define: {
    "process.env.REACT_APP_SPRING_BOOT_URL": JSON.stringify(
      process.env.REACT_APP_SPRING_BOOT_URL || "http://localhost:8080"
    ),
    "process.env.REACT_APP_FASTAPI_URL": JSON.stringify(
      process.env.REACT_APP_FASTAPI_URL || "https://localhost:8443"
    ),
  },
});