/**
 * Main React application with auth, dashboard, and secure viewer routes.
 */

import React, { useEffect, useState } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { DocumentPage } from "./pages/DocumentPage";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { AuditLogsPage } from "./pages/AuditLogsPage";
import { apiClient } from "./services/api";
import { BrandOverlay } from "./components/BrandOverlay";

function App() {
  const [accessToken, setAccessToken] = useState<string | null>(() =>
    typeof window !== "undefined" ? localStorage.getItem("accessToken") : null
  );

  useEffect(() => {
    const sync = () => {
      const t = localStorage.getItem("accessToken");
      setAccessToken(t);
      // Do NOT call setAuthToken/clearAuthToken here — they emit p3-access-token-changed
      // and would recurse until stack overflow. Interceptor reads localStorage per request.
      apiClient.applyAuthSnapshotFromStorage();
    };
    window.addEventListener("storage", sync);
    window.addEventListener("p3-access-token-changed", sync);
    sync();
    return () => {
      window.removeEventListener("storage", sync);
      window.removeEventListener("p3-access-token-changed", sync);
    };
  }, []);

  useEffect(() => {
    const originalPrint = window.print;
    window.print = function () {
      console.warn("Print is disabled in the secure viewer");
      return undefined;
    };
    return () => {
      window.print = originalPrint;
    };
  }, []);

  return (
    <Router>
      <BrandOverlay />
      {/* Logos stay fixed underneath so top-left headings, nav links and menus remain visible */}
      <div
        style={{
          position: "relative",
          zIndex: 10,
          minHeight: "100vh",
          isolation: "isolate",
        }}
      >
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/admin/audit-logs" element={<AuditLogsPage />} />
          <Route
            path="/documents/:documentId"
            element={<DocumentPage accessToken={accessToken} />}
          />
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
