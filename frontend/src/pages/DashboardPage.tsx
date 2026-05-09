/**
 * Document list, upload, grant, and revoke flows.
 */

import React, { Fragment, useCallback, useEffect, FormEvent, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  apiClient,
  DocumentGrantShare,
  DocumentSummary,
} from "../services/api";

type DocumentListScope = "owned" | "shared";

function getStoredRoles(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem("p3_roles");
    if (!raw) return [];
    const p = JSON.parse(raw) as unknown;
    return Array.isArray(p) ? (p as string[]) : [];
  } catch {
    return [];
  }
}

function userIsAdmin(): boolean {
  return getStoredRoles().includes("ADMIN");
}

function shareBadgeStyle(
  status: string
): { background: string; color: string; label: string } {
  switch (status) {
    case "ACTIVE":
      return { background: "#e8f5e9", color: "#1b5e20", label: "ACTIVE" };
    case "PENDING":
      return { background: "#fff8e1", color: "#f57f17", label: "PENDING" };
    case "EXPIRED":
      return { background: "#ffebee", color: "#b71c1c", label: "EXPIRED" };
    case "REVOKED":
      return { background: "#ffebee", color: "#b71c1c", label: "REVOKED" };
    default:
      return { background: "#f5f5f5", color: "#424242", label: status };
  }
}

function fmtWhen(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

/** Shared-tab row: validity window for the viewer. */
function sharedAccessSchedule(d: DocumentSummary): string {
  if (!d.validFrom || !d.expiresAt) {
    return "—";
  }
  return `${fmtWhen(d.validFrom)} → ${fmtWhen(d.expiresAt)}`;
}

function defaultExpiryLocal(): string {
  const dt = new Date();
  dt.setHours(dt.getHours() + 24);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}T${pad(
    dt.getHours()
  )}:${pad(dt.getMinutes())}`;
}

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const [documents, setDocuments] = useState<DocumentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [uploadErr, setUploadErr] = useState<string | null>(null);
  const [expandedDocId, setExpandedDocId] = useState<string | null>(null);
  const [listScope, setListScope] = useState<DocumentListScope>("owned");
  const [sharedGrantDeletingId, setSharedGrantDeletingId] = useState<string | null>(null);

  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadBusy, setUploadBusy] = useState(false);

  const userId = useMemo(
    () => (typeof window !== "undefined" ? localStorage.getItem("p3_userId") : null),
    []
  );
  const isAdmin = userIsAdmin();

  const load = useCallback(async () => {
    setErr(null);
    setLoading(true);
    try {
      const list = await apiClient.listDocuments(0, 50, listScope);
      setDocuments(list);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load documents");
    } finally {
      setLoading(false);
    }
  }, [listScope]);

  useEffect(() => {
    if (!localStorage.getItem("accessToken")) {
      navigate("/login", { replace: true });
      return;
    }
    load();
  }, [load, navigate]);

  const onGranteeRemoveExpiredRow = async (d: DocumentSummary) => {
    if (!d.grantId || d.shareStatus !== "EXPIRED") {
      return;
    }
    if (
      !window.confirm(
        "Remove this expired access entry from your list? This does not delete the document."
      )
    ) {
      return;
    }
    setSharedGrantDeletingId(d.grantId);
    setErr(null);
    try {
      await apiClient.deleteGrant(d.documentId, d.grantId);
      await load();
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Could not remove entry");
    } finally {
      setSharedGrantDeletingId(null);
    }
  };

  const onUpload = async (e: FormEvent) => {
    e.preventDefault();
    if (!uploadFile) return;
    setUploadBusy(true);
    setUploadErr(null);
    try {
      const { documentId } = await apiClient.uploadPdf(uploadFile);
      setUploadFile(null);
      await load();
      navigate(`/documents/${documentId}`);
    } catch (ex) {
      setUploadErr(ex instanceof Error ? ex.message : "Upload failed");
    } finally {
      setUploadBusy(false);
    }
  };

  return (
    <div
      style={{
        margin: "24px auto",
        maxWidth: 960,
        padding: 16,
        fontFamily: 'system-ui, "Segoe UI", sans-serif',
        color: "#1a1a1a",
      }}
    >
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
        <h1 style={{ margin: 0, fontSize: 28, fontWeight: 600 }}>Documents</h1>
        <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
          {isAdmin && (
            <Link to="/admin/audit-logs" style={{ fontWeight: 600 }}>
              Audit logs
            </Link>
          )}
          <span style={{ marginRight: 12 }}>{localStorage.getItem("p3_username")}</span>
          <button
            type="button"
            onClick={() => {
              apiClient.clearAuthToken();
              localStorage.removeItem("p3_userId");
              localStorage.removeItem("p3_username");
              localStorage.removeItem("p3_roles");
              navigate("/login");
            }}
          >
            Sign out
          </button>
        </div>
      </header>

      <section
        style={{
          marginTop: 24,
          padding: 20,
          border: "1px solid #e0e0e0",
          borderRadius: 12,
          background: "#fafafa",
        }}
      >
        <h2 style={{ marginTop: 0, fontSize: 18 }}>Upload PDF (encrypted server-side)</h2>
        <p style={{ margin: "8px 0 16px", color: "#555", fontSize: 14 }}>
          The file is encrypted with AES-256-GCM before storage. Only people you grant can open it in the viewer.
          The original file name is saved as the document name and is visible only to you as the owner; others see a
          generic label.
        </p>
        <form onSubmit={onUpload} style={{ display: "flex", flexWrap: "wrap", gap: 12, alignItems: "flex-end" }}>
          <label>
            PDF file{" "}
            <input
              type="file"
              accept="application/pdf"
              onChange={(e) => setUploadFile(e.target.files?.[0] ?? null)}
              required
            />
          </label>
          <button
            type="submit"
            disabled={uploadBusy}
            style={{
              padding: "8px 20px",
              background: uploadBusy ? "#ccc" : "#1565c0",
              color: "#fff",
              border: "none",
              borderRadius: 8,
              cursor: uploadBusy ? "not-allowed" : "pointer",
              fontWeight: 600,
            }}
          >
            {uploadBusy ? "Encrypting…" : "Upload & encrypt"}
          </button>
        </form>
        {uploadErr && (
          <div
            style={{
              marginTop: 16,
              padding: 12,
              background: "#ffebee",
              border: "1px solid #ffcdd2",
              borderRadius: 8,
              color: "#b71c1c",
              fontSize: 14,
            }}
            role="alert"
          >
            {uploadErr}
          </div>
        )}
      </section>

      <nav
        style={{ marginTop: 24, display: "flex", gap: 0, flexWrap: "wrap", borderBottom: "1px solid #ccc" }}
        aria-label="Document collections"
      >
        <button
          type="button"
          role="tab"
          aria-selected={listScope === "owned"}
          onClick={() => {
            setListScope("owned");
            setExpandedDocId(null);
          }}
          style={{
            padding: "12px 20px",
            border: "none",
            borderBottom: listScope === "owned" ? "3px solid #1565c0" : "3px solid transparent",
            background: listScope === "owned" ? "#e3f2fd" : "#f5f5f5",
            cursor: "pointer",
            fontWeight: listScope === "owned" ? 600 : 500,
            fontSize: 15,
          }}
        >
          My uploaded files
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={listScope === "shared"}
          onClick={() => {
            setListScope("shared");
            setExpandedDocId(null);
          }}
          style={{
            padding: "12px 20px",
            border: "none",
            borderBottom:
              listScope === "shared" ? "3px solid #1565c0" : "3px solid transparent",
            background: listScope === "shared" ? "#e3f2fd" : "#f5f5f5",
            cursor: "pointer",
            fontWeight: listScope === "shared" ? 600 : 500,
            fontSize: 15,
          }}
        >
          Files I have access to
        </button>
      </nav>

      {loading && <p style={{ marginTop: 24 }}>Loading documents…</p>}
      {err && (
        <p style={{ marginTop: 24, color: "#b00020" }} role="alert">
          {err}
        </p>
      )}

      {!loading && documents.length === 0 && (
        <p style={{ marginTop: 24, color: "#666", fontSize: 15 }}>
          {listScope === "owned"
            ? "You have not uploaded any files yet."
            : "No files shared with you yet."}
        </p>
      )}
      {!loading && documents.length > 0 && listScope === "shared" && (
        <table style={{ width: "100%", marginTop: 24, borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left", borderBottom: "1px solid #ccc" }}>
              <th style={{ padding: 8 }}>Document</th>
              <th style={{ padding: 8 }}>Your access status</th>
              <th style={{ padding: 8 }}>Access window</th>
              <th style={{ padding: 8 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {documents.map((d) => {
              const badgeStyle = shareBadgeStyle(d.shareStatus ?? "");
              return (
                <tr key={d.documentId} style={{ borderBottom: "1px solid #eee" }}>
                  <td style={{ padding: 8 }}>{d.title}</td>
                  <td style={{ padding: 8 }}>
                    <span
                      style={{
                        display: "inline-block",
                        padding: "2px 10px",
                        borderRadius: 999,
                        fontWeight: 700,
                        fontSize: 11,
                        background: badgeStyle.background,
                        color: badgeStyle.color,
                      }}
                    >
                      {badgeStyle.label}
                    </span>
                  </td>
                  <td style={{ padding: 8, fontSize: 13, color: "#333" }}>
                    {sharedAccessSchedule(d)}
                  </td>
                  <td style={{ padding: 8 }}>
                    <Link to={`/documents/${d.documentId}`} style={{ marginRight: 12 }}>
                      View
                    </Link>
                    {d.shareStatus === "EXPIRED" && d.grantId && (
                      <button
                        type="button"
                        disabled={sharedGrantDeletingId === d.grantId}
                        onClick={() => onGranteeRemoveExpiredRow(d)}
                        style={{
                          padding: "4px 10px",
                          fontSize: 12,
                          borderRadius: 6,
                          border: "1px solid #757575",
                          background: "#f5f5f5",
                          cursor:
                            sharedGrantDeletingId === d.grantId ? "not-allowed" : "pointer",
                        }}
                      >
                        {sharedGrantDeletingId === d.grantId ? "…" : "Remove"}
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {!loading && documents.length > 0 && listScope !== "shared" && (
        <table style={{ width: "100%", marginTop: 24, borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left", borderBottom: "1px solid #ccc" }}>
              <th style={{ padding: 8 }}>Document</th>
              <th style={{ padding: 8 }}>Document ID</th>
              <th style={{ padding: 8 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {documents.map((d) => {
              const isOwner = userId === d.ownerId;
              const canSeeShares = isOwner || isAdmin;
              const expanded = expandedDocId === d.documentId;
              return (
                <Fragment key={d.documentId}>
                  <tr style={{ borderBottom: "1px solid #eee" }}>
                    <td style={{ padding: 8 }}>{d.title}</td>
                    <td style={{ padding: 8, fontSize: 12 }}>{d.documentId}</td>
                    <td style={{ padding: 8 }}>
                      <Link to={`/documents/${d.documentId}`} style={{ marginRight: 12 }}>
                        View
                      </Link>
                      {canSeeShares && (
                        <button
                          type="button"
                          onClick={() =>
                            setExpandedDocId((prev) =>
                              prev === d.documentId ? null : d.documentId
                            )
                          }
                          style={{
                            marginRight: 12,
                            padding: "4px 10px",
                            borderRadius: 6,
                            border: "1px solid #bdbdbd",
                            background: expanded ? "#e3f2fd" : "#fff",
                            cursor: "pointer",
                            fontSize: 13,
                          }}
                        >
                          {expanded ? "Hide shares" : "Who has access"}
                        </button>
                      )}
                    </td>
                  </tr>
                  {expanded && canSeeShares && (
                    <tr>
                      <td
                        colSpan={3}
                        style={{
                          padding: "14px 12px",
                          background: "#fafbfc",
                          borderBottom: "1px solid #e0e0e0",
                        }}
                      >
                        <strong style={{ display: "block", marginBottom: 10, fontSize: 14 }}>
                          Who has access
                        </strong>
                        <ShareAccessPanel
                          documentId={d.documentId}
                          canManageShares={canSeeShares}
                          onAccessChanged={load}
                        />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
};

const ShareAccessPanel: React.FC<{
  documentId: string;
  canManageShares: boolean;
  onAccessChanged?: () => void;
}> = ({ documentId, canManageShares, onAccessChanged }) => {
  const [loading, setLoading] = useState(true);
  const [panelErr, setPanelErr] = useState<string | null>(null);
  const [grants, setGrants] = useState<DocumentGrantShare[]>([]);
  const [grantUsername, setGrantUsername] = useState("");
  const [expiresLocal, setExpiresLocal] = useState(() => defaultExpiryLocal());
  const [grantBusy, setGrantBusy] = useState(false);
  const [grantMsg, setGrantMsg] = useState<string | null>(null);
  const [revokingGrantId, setRevokingGrantId] = useState<string | null>(null);
  const [deletingGrantId, setDeletingGrantId] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setPanelErr(null);
    try {
      const st = await apiClient.getDocumentStatus(documentId);
      setGrants(st.grants ?? []);
    } catch (e) {
      setPanelErr(e instanceof Error ? e.message : "Failed to load shared access");
    } finally {
      setLoading(false);
    }
  }, [documentId]);

  useEffect(() => {
    setGrantUsername("");
    setExpiresLocal(defaultExpiryLocal());
    setGrantMsg(null);
    reload();
  }, [reload]);

  const onGrantSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const u = grantUsername.trim();
    if (!u) return;
    setGrantBusy(true);
    setGrantMsg(null);
    try {
      await apiClient.grantAccess(documentId, {
        granteeUsername: u,
        expiresAt: new Date(expiresLocal).toISOString(),
      });
      setGrantUsername("");
      setExpiresLocal(defaultExpiryLocal());
      await reload();
      onAccessChanged?.();
    } catch (ex) {
      setGrantMsg(ex instanceof Error ? ex.message : "Grant failed");
    } finally {
      setGrantBusy(false);
    }
  };

  const onRevoke = async (g: DocumentGrantShare) => {
    const name = g.granteeUsername?.trim();
    if (!name) return;
    setRevokingGrantId(g.grantId);
    setPanelErr(null);
    try {
      await apiClient.revokeAccess(documentId, { granteeUsername: name });
      await reload();
      onAccessChanged?.();
    } catch (ex) {
      setPanelErr(ex instanceof Error ? ex.message : "Revoke failed");
    } finally {
      setRevokingGrantId(null);
    }
  };

  const onDeleteGrant = async (g: DocumentGrantShare) => {
    if (
      !window.confirm(
        "Remove this user from the access list? If access is still active, it will be revoked and this row will be deleted."
      )
    ) {
      return;
    }
    setDeletingGrantId(g.grantId);
    setPanelErr(null);
    try {
      await apiClient.deleteGrant(documentId, g.grantId);
      await reload();
      onAccessChanged?.();
    } catch (ex) {
      setPanelErr(ex instanceof Error ? ex.message : "Delete failed");
    } finally {
      setDeletingGrantId(null);
    }
  };

  return (
    <div style={{ maxWidth: 820 }}>
      {canManageShares && (
        <form
          onSubmit={onGrantSubmit}
          style={{
            marginBottom: 16,
            padding: 14,
            background: "#fff",
            border: "1px solid #e0e0e0",
            borderRadius: 8,
            display: "flex",
            flexWrap: "wrap",
            gap: 12,
            alignItems: "flex-end",
          }}
        >
          <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 13 }}>
            Username
            <input
              value={grantUsername}
              onChange={(e) => setGrantUsername(e.target.value)}
              placeholder="Existing user login"
              required
              style={{ minWidth: 200, padding: "6px 8px" }}
            />
          </label>
          <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 13 }}>
            Access until (local)
            <input
              type="datetime-local"
              value={expiresLocal}
              onChange={(e) => setExpiresLocal(e.target.value)}
              required
              style={{ padding: "6px 8px" }}
            />
          </label>
          <button
            type="submit"
            disabled={grantBusy}
            style={{
              padding: "8px 16px",
              background: grantBusy ? "#ccc" : "#2e7d32",
              color: "#fff",
              border: "none",
              borderRadius: 6,
              fontWeight: 600,
              cursor: grantBusy ? "not-allowed" : "pointer",
            }}
          >
            {grantBusy ? "Adding…" : "Grant access"}
          </button>
          {grantMsg && (
            <p style={{ margin: 0, color: "#b00020", fontSize: 13, width: "100%" }}>{grantMsg}</p>
          )}
        </form>
      )}

      {loading && <p style={{ margin: 0, color: "#666", fontSize: 14 }}>Loading…</p>}
      {!loading && panelErr && (
        <p style={{ margin: 0, color: "#b00020", fontSize: 14 }} role="alert">
          {panelErr}
        </p>
      )}
      {!loading && !panelErr && grants.length === 0 && (
        <p style={{ margin: "8px 0 0", color: "#666", fontSize: 14 }}>
          No one has been granted access yet.
        </p>
      )}
      {!loading && !panelErr && grants.length > 0 && (
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            fontSize: 13,
            background: "#fff",
            border: "1px solid #e0e0e0",
            borderRadius: 8,
          }}
        >
          <thead>
            <tr style={{ textAlign: "left", background: "#f5f5f5" }}>
              <th style={{ padding: 8 }}>Username</th>
              <th style={{ padding: 8 }}>Status</th>
              <th style={{ padding: 8 }}>Valid from</th>
              <th style={{ padding: 8 }}>Expires</th>
              {canManageShares && <th style={{ padding: 8 }}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {grants.map((g) => {
              const badge = shareBadgeStyle(g.shareStatus);
              const displayName =
                (g.granteeUsername && g.granteeUsername.trim()) ||
                `${(g.granteeUserId ?? "").slice(0, 8)}…`;
              const canRevoke =
                canManageShares &&
                (g.shareStatus === "ACTIVE" || g.shareStatus === "PENDING");
              const rowBusy =
                revokingGrantId === g.grantId || deletingGrantId === g.grantId;
              return (
                <tr key={g.grantId} style={{ borderTop: "1px solid #eee" }}>
                  <td style={{ padding: 8, fontWeight: 600 }}>{displayName}</td>
                  <td style={{ padding: 8 }}>
                    <span
                      style={{
                        display: "inline-block",
                        padding: "2px 10px",
                        borderRadius: 999,
                        fontWeight: 700,
                        fontSize: 11,
                        letterSpacing: 0.5,
                        background: badge.background,
                        color: badge.color,
                      }}
                    >
                      {badge.label}
                    </span>
                  </td>
                  <td style={{ padding: 8, whiteSpace: "nowrap" }}>{fmtWhen(g.validFrom)}</td>
                  <td style={{ padding: 8, whiteSpace: "nowrap" }}>{fmtWhen(g.expiresAt)}</td>
                  {canManageShares && (
                    <td style={{ padding: 8 }}>
                      <div
                        style={{
                          display: "flex",
                          flexWrap: "wrap",
                          gap: 8,
                          alignItems: "center",
                        }}
                      >
                        {canRevoke && (
                          <button
                            type="button"
                            disabled={rowBusy}
                            onClick={() => onRevoke(g)}
                            style={{
                              padding: "4px 10px",
                              fontSize: 12,
                              borderRadius: 6,
                              border: "1px solid #c62828",
                              background: "#ffebee",
                              color: "#b71c1c",
                              cursor: rowBusy ? "not-allowed" : "pointer",
                            }}
                          >
                            {revokingGrantId === g.grantId ? "…" : "Revoke"}
                          </button>
                        )}
                        <button
                          type="button"
                          disabled={rowBusy}
                          onClick={() => onDeleteGrant(g)}
                          title="Remove this grant from the list (revokes first if needed)"
                          style={{
                            padding: "4px 10px",
                            fontSize: 12,
                            borderRadius: 6,
                            border: "1px solid #757575",
                            background: "#f5f5f5",
                            color: "#424242",
                            cursor: rowBusy ? "not-allowed" : "pointer",
                          }}
                        >
                          {deletingGrantId === g.grantId ? "…" : "Delete"}
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
};
