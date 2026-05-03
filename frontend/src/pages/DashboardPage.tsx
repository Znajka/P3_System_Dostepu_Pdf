/**
 * Document list, upload, grant, and revoke flows.
 */

import React, { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiClient, DocumentSummary } from "../services/api";

type IdMode = "username" | "email" | "userid";

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [documents, setDocuments] = useState<DocumentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const [uploadTitle, setUploadTitle] = useState("My document");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadBusy, setUploadBusy] = useState(false);

  const userId = useMemo(
    () => (typeof window !== "undefined" ? localStorage.getItem("p3_userId") : null),
    []
  );

  const load = useCallback(async () => {
    setErr(null);
    setLoading(true);
    try {
      const list = await apiClient.listDocuments(0, 50);
      setDocuments(list);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load documents");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!localStorage.getItem("accessToken")) {
      navigate("/login", { replace: true });
      return;
    }
    load();
  }, [load, navigate]);

  const onUpload = async (e: FormEvent) => {
    e.preventDefault();
    if (!uploadFile) return;
    setUploadBusy(true);
    setErr(null);
    try {
      const { documentId } = await apiClient.uploadPdf(uploadFile, uploadTitle);
      setUploadFile(null);
      await load();
      navigate(`/documents/${documentId}`);
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Upload failed");
    } finally {
      setUploadBusy(false);
    }
  };

  return (
    <div style={{ margin: "24px auto", maxWidth: 960, padding: 16, fontFamily: "system-ui, sans-serif" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h1 style={{ margin: 0 }}>Documents</h1>
        <div>
          <span style={{ marginRight: 12 }}>{localStorage.getItem("p3_username")}</span>
          <button
            type="button"
            onClick={() => {
              apiClient.clearAuthToken();
              localStorage.removeItem("p3_userId");
              localStorage.removeItem("p3_username");
              navigate("/login");
            }}
          >
            Sign out
          </button>
        </div>
      </header>

      <section style={{ marginTop: 24, padding: 16, border: "1px solid #ddd", borderRadius: 8 }}>
        <h2 style={{ marginTop: 0 }}>Upload PDF</h2>
        <form onSubmit={onUpload} style={{ display: "flex", flexWrap: "wrap", gap: 12, alignItems: "flex-end" }}>
          <label>
            Title{" "}
            <input value={uploadTitle} onChange={(e) => setUploadTitle(e.target.value)} required />
          </label>
          <label>
            File{" "}
            <input
              type="file"
              accept="application/pdf"
              onChange={(e) => setUploadFile(e.target.files?.[0] ?? null)}
              required
            />
          </label>
          <button type="submit" disabled={uploadBusy}>
            {uploadBusy ? "Uploading…" : "Upload"}
          </button>
        </form>
      </section>

      {loading && <p style={{ marginTop: 24 }}>Loading documents…</p>}
      {err && (
        <p style={{ marginTop: 24, color: "#b00020" }} role="alert">
          {err}
        </p>
      )}

      {!loading && (
        <table style={{ width: "100%", marginTop: 24, borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left", borderBottom: "1px solid #ccc" }}>
              <th style={{ padding: 8 }}>Title</th>
              <th style={{ padding: 8 }}>Document ID</th>
              <th style={{ padding: 8 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {documents.map((d) => (
              <tr key={d.documentId} style={{ borderBottom: "1px solid #eee" }}>
                <td style={{ padding: 8 }}>{d.title}</td>
                <td style={{ padding: 8, fontSize: 12 }}>{d.documentId}</td>
                <td style={{ padding: 8 }}>
                  <Link to={`/documents/${d.documentId}`} style={{ marginRight: 12 }}>
                    View
                  </Link>
                  {userId === d.ownerId && (
                    <>
                      <GrantRevokeButtons documentId={d.documentId} onDone={load} />
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

const GrantRevokeButtons: React.FC<{ documentId: string; onDone: () => void }> = ({
  documentId,
  onDone,
}) => {
  const [openGrant, setOpenGrant] = useState(false);
  const [openRevoke, setOpenRevoke] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpenGrant(true)} style={{ marginRight: 8 }}>
        Grant
      </button>
      <button type="button" onClick={() => setOpenRevoke(true)}>
        Revoke
      </button>
      {openGrant && (
        <GrantModal
          documentId={documentId}
          onClose={() => setOpenGrant(false)}
          onDone={() => {
            setOpenGrant(false);
            onDone();
          }}
        />
      )}
      {openRevoke && (
        <RevokeModal
          documentId={documentId}
          onClose={() => setOpenRevoke(false)}
          onDone={() => {
            setOpenRevoke(false);
            onDone();
          }}
        />
      )}
    </>
  );
};

const GrantModal: React.FC<{
  documentId: string;
  onClose: () => void;
  onDone: () => void;
}> = ({ documentId, onClose, onDone }) => {
  const [mode, setMode] = useState<IdMode>("username");
  const [value, setValue] = useState("");
  const [expiresLocal, setExpiresLocal] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const expiresAt = new Date(expiresLocal).toISOString();
      const body: Parameters<typeof apiClient.grantAccess>[1] = { expiresAt };
      if (mode === "username") body.granteeUsername = value.trim();
      else if (mode === "email") body.granteeEmail = value.trim();
      else body.granteeUserId = value.trim();
      await apiClient.grantAccess(documentId, body);
      onDone();
    } catch (ex) {
      setMsg(ex instanceof Error ? ex.message : "Grant failed");
    } finally {
      setBusy(false);
    }
  };

  const defExp = (): string => {
    const dt = new Date();
    dt.setHours(dt.getHours() + 24);
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}T${pad(
      dt.getHours()
    )}:${pad(dt.getMinutes())}`;
  };

  React.useEffect(() => {
    if (!expiresLocal) {
      setExpiresLocal(defExp());
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.35)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
      role="dialog"
      aria-modal
    >
      <div style={{ background: "#fff", padding: 24, borderRadius: 8, minWidth: 360 }}>
        <h3 style={{ marginTop: 0 }}>Grant access</h3>
        <form onSubmit={submit}>
          <div style={{ marginBottom: 12 }}>
            <label style={{ marginRight: 16 }}>
              <input
                type="radio"
                name="mode"
                checked={mode === "username"}
                onChange={() => setMode("username")}
              />{" "}
              Username
            </label>
            <label style={{ marginRight: 16 }}>
              <input
                type="radio"
                checked={mode === "email"}
                onChange={() => setMode("email")}
              />{" "}
              Email
            </label>
            <label>
              <input
                type="radio"
                checked={mode === "userid"}
                onChange={() => setMode("userid")}
              />{" "}
              User ID
            </label>
          </div>
          <label style={{ display: "block", marginBottom: 12 }}>
            Grantee{" "}
            <input value={value} onChange={(e) => setValue(e.target.value)} required style={{ width: "100%" }} />
          </label>
          <label style={{ display: "block", marginBottom: 12 }}>
            Expires (local){" "}
            <input
              type="datetime-local"
              value={expiresLocal}
              onChange={(e) => setExpiresLocal(e.target.value)}
              required
              style={{ width: "100%" }}
            />
          </label>
          {msg && <p style={{ color: "#b00020" }}>{msg}</p>}
          <div style={{ marginTop: 16, display: "flex", gap: 12 }}>
            <button type="submit" disabled={busy}>
              {busy ? "Saving…" : "Grant"}
            </button>
            <button type="button" onClick={onClose}>
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const RevokeModal: React.FC<{
  documentId: string;
  onClose: () => void;
  onDone: () => void;
}> = ({ documentId, onClose, onDone }) => {
  const [mode, setMode] = useState<IdMode>("username");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const body: Parameters<typeof apiClient.revokeAccess>[1] = {};
      if (mode === "username") body.granteeUsername = value.trim();
      else if (mode === "email") body.granteeEmail = value.trim();
      else body.granteeUserId = value.trim();
      await apiClient.revokeAccess(documentId, body);
      onDone();
    } catch (ex) {
      setMsg(ex instanceof Error ? ex.message : "Revoke failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.35)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
      role="dialog"
      aria-modal
    >
      <div style={{ background: "#fff", padding: 24, borderRadius: 8, minWidth: 360 }}>
        <h3 style={{ marginTop: 0 }}>Revoke access</h3>
        <form onSubmit={submit}>
          <div style={{ marginBottom: 12 }}>
            <label style={{ marginRight: 16 }}>
              <input
                type="radio"
                checked={mode === "username"}
                onChange={() => setMode("username")}
              />{" "}
              Username
            </label>
            <label style={{ marginRight: 16 }}>
              <input
                type="radio"
                checked={mode === "email"}
                onChange={() => setMode("email")}
              />{" "}
              Email
            </label>
            <label>
              <input
                type="radio"
                checked={mode === "userid"}
                onChange={() => setMode("userid")}
              />{" "}
              User ID
            </label>
          </div>
          <label style={{ display: "block", marginBottom: 12 }}>
            Grantee{" "}
            <input value={value} onChange={(e) => setValue(e.target.value)} required style={{ width: "100%" }} />
          </label>
          {msg && <p style={{ color: "#b00020" }}>{msg}</p>}
          <div style={{ marginTop: 16, display: "flex", gap: 12 }}>
            <button type="submit" disabled={busy}>
              {busy ? "Revoking…" : "Revoke"}
            </button>
            <button type="button" onClick={onClose}>
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
