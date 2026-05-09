/**
 * JWT login against Spring Boot `/api/auth/login`.
 */

import React, { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { apiClient } from "../services/api";

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await apiClient.login(username.trim(), password);
      apiClient.setAuthToken(res.accessToken);
      if (typeof localStorage !== "undefined") {
        localStorage.setItem("p3_userId", res.userId);
        localStorage.setItem("p3_username", res.username);
        localStorage.setItem("p3_roles", JSON.stringify(res.roles ?? []));
      }
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      style={{
        maxWidth: 400,
        margin: "48px auto",
        padding: 24,
        fontFamily: "system-ui, sans-serif",
        border: "1px solid #ccc",
        borderRadius: 8,
      }}
    >
      <h1 style={{ marginTop: 0 }}>Sign in</h1>
      <p style={{ color: "#555" }}>
        Demo: admin/admin123 · alice/alice123 · bob/bob123 · carol/carol123 · dave/dave123
      </p>
      <form onSubmit={onSubmit}>
        <label style={{ display: "block", marginBottom: 8 }}>
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            style={{ display: "block", width: "100%", padding: 8, marginTop: 4 }}
          />
        </label>
        <label style={{ display: "block", marginBottom: 16 }}>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            style={{ display: "block", width: "100%", padding: 8, marginTop: 4 }}
          />
        </label>
        {error && (
          <p style={{ color: "#b00020", marginBottom: 12 }} role="alert">
            {error}
          </p>
        )}
        <button type="submit" disabled={busy} style={{ padding: "10px 20px" }}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
};
