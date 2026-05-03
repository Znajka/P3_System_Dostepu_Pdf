/**
 * Main React application with auth, dashboard, and secure viewer routes.
 */

import React, { useEffect, useState } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { DocumentPage } from "./pages/DocumentPage";
import { LoginPage } from "./pages/LoginPage";
import { DashboardPage } from "./pages/DashboardPage";
import { apiClient } from "./services/api";

function App() {
  const [accessToken, setAccessToken] = useState<string | null>(() =>
    typeof window !== "undefined" ? localStorage.getItem("accessToken") : null
  );

  useEffect(() => {
    const sync = () => {
      const t = localStorage.getItem("accessToken");
      setAccessToken(t);
      if (t) {
        apiClient.setAuthToken(t);
      } else {
        apiClient.clearAuthToken();
      }
    };
    window.addEventListener("storage", sync);
    sync();
    return () => window.removeEventListener("storage", sync);
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
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route
          path="/documents/:documentId"
          element={<DocumentPage accessToken={accessToken} />}
        />
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
