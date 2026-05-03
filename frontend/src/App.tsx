/**
 * Main React application with secure viewer wrapper.
 */

import React, { useEffect, useState } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { DocumentPage } from "./pages/DocumentPage";

function App() {
  const [accessToken, setAccessToken] = useState<string | null>(null);

  useEffect(() => {
    // Load token from localStorage on mount
    const token = localStorage.getItem("accessToken");
    setAccessToken(token);
  }, []);

  // Disable browser print function
  useEffect(() => {
    const originalPrint = window.print;
    window.print = function () {
      console.warn("Print functionality is disabled for security");
      return undefined;
    };

    return () => {
      window.print = originalPrint;
    };
  }, []);

  return (
    <Router>
      <Routes>
        <Route
          path="/documents/:documentId"
          element={<DocumentPage accessToken={accessToken} />}
        />
        <Route path="/" element={<Navigate to="/documents/doc-123" replace />} />
      </Routes>
    </Router>
  );
}

export default App;