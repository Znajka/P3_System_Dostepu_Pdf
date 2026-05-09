/**
 * Admin-only: browse access event audit log (Spring GET /api/logs/access-events).
 */

import React, { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiClient, AccessEventEntry } from "../services/api";

const PAGE_SIZE = 50;

/** Must match backend AccessAction enum names (valueOf). */
const ACTION_FILTER_OPTIONS = [
  "",
  "UPLOAD",
  "GRANT",
  "REVOKE",
  "OPEN_ATTEMPT",
  "STREAM_START",
  "STREAM_END",
] as const;

const RESULT_FILTER_OPTIONS = ["", "SUCCESS", "FAILURE"] as const;

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

function formatAction(action: string): string {
  return action.replace(/_/g, " ").toLowerCase();
}

export const AuditLogsPage: React.FC = () => {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);
  const [total, setTotal] = useState(0);
  const [events, setEvents] = useState<AccessEventEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [filterAction, setFilterAction] = useState<string>("");
  const [filterResult, setFilterResult] = useState<string>("");
  const [filterUserId, setFilterUserId] = useState<string>("");
  /** True after "Apply filters" with at least one criterion (for empty-state copy). */
  const [filtersActive, setFiltersActive] = useState(false);

  const fetchPage = useCallback(
    async (pageIndex: number) => {
      setErr(null);
      setLoading(true);
      try {
        const uid = filterUserId.trim();
        const data = await apiClient.getAccessEventLogs({
          limit: PAGE_SIZE,
          offset: pageIndex * PAGE_SIZE,
          ...(filterAction ? { action: filterAction } : {}),
          ...(filterResult ? { result: filterResult } : {}),
          ...(uid ? { userId: uid } : {}),
        });
        setEvents(data.events ?? []);
        setTotal(typeof data.total === "number" ? data.total : 0);
        setPage(pageIndex);
      } catch (e) {
        const msg =
          e instanceof Error ? e.message : "Unable to load audit log";
        setErr(msg);
        setEvents([]);
      } finally {
        setLoading(false);
      }
    },
    [filterAction, filterResult, filterUserId]
  );

  useEffect(() => {
    if (!localStorage.getItem("accessToken")) {
      navigate("/login", { replace: true });
      return;
    }
    if (!getStoredRoles().includes("ADMIN")) {
      navigate("/dashboard", { replace: true });
      return;
    }
    fetchPage(0);
  }, [fetchPage, navigate]);

  const offset = page * PAGE_SIZE;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE) || 1);
  const canPrev = page > 0 && !loading;
  const canNext = !loading && total > 0 && offset + PAGE_SIZE < total;

  const applyFilters = () => {
    setFiltersActive(
      !!(filterAction || filterResult || filterUserId.trim())
    );
    void fetchPage(0);
  };

  const clearFiltersAndRefetch = async () => {
    setFiltersActive(false);
    setFilterAction("");
    setFilterResult("");
    setFilterUserId("");
    setErr(null);
    setLoading(true);
    try {
      const data = await apiClient.getAccessEventLogs({
        limit: PAGE_SIZE,
        offset: 0,
      });
      setEvents(data.events ?? []);
      setTotal(typeof data.total === "number" ? data.total : 0);
      setPage(0);
    } catch (e) {
      const msg =
        e instanceof Error ? e.message : "Unable to load audit log";
      setErr(msg);
      setEvents([]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        margin: "24px auto",
        maxWidth: 1400,
        padding: 16,
        fontFamily: 'system-ui, "Segoe UI", sans-serif',
        color: "#1a1a1a",
      }}
    >
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 12,
        }}
      >
        <div>
          <h1 style={{ margin: 0, fontSize: 24 }}>Audit log</h1>
          <p style={{ margin: "8px 0 0", color: "#555", fontSize: 14 }}>
            Security-relevant events (grants, revokes, open attempts, uploads, streams).
          </p>
        </div>
        <nav style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <Link to="/dashboard">← Dashboard</Link>
          <button
            type="button"
            disabled={loading}
            onClick={() => fetchPage(page)}
            style={{ padding: "6px 14px" }}
          >
            Refresh
          </button>
        </nav>
      </header>

      {err && (
        <p style={{ marginTop: 16, padding: 12, background: "#ffebee", borderRadius: 8, color: "#b71c1c" }}>
          {err}
        </p>
      )}

      <section
        style={{
          marginTop: 20,
          padding: 16,
          background: "#f8f9fa",
          border: "1px solid #e0e0e0",
          borderRadius: 8,
          display: "flex",
          flexWrap: "wrap",
          gap: 12,
          alignItems: "flex-end",
        }}
      >
        <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 13 }}>
          <span style={{ fontWeight: 600, color: "#333" }}>Action</span>
          <select
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            style={{ padding: "6px 10px", minWidth: 160 }}
          >
            {ACTION_FILTER_OPTIONS.map((v) => (
              <option key={v || "all"} value={v}>
                {v ? formatAction(v) : "All actions"}
              </option>
            ))}
          </select>
        </label>
        <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 13 }}>
          <span style={{ fontWeight: 600, color: "#333" }}>Result</span>
          <select
            value={filterResult}
            onChange={(e) => setFilterResult(e.target.value)}
            style={{ padding: "6px 10px", minWidth: 120 }}
          >
            <option value="">All results</option>
            {RESULT_FILTER_OPTIONS.filter(Boolean).map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 13, flex: "1 1 240px" }}>
          <span style={{ fontWeight: 600, color: "#333" }}>User ID</span>
          <input
            type="text"
            placeholder="UUID (optional)"
            value={filterUserId}
            onChange={(e) => setFilterUserId(e.target.value)}
            style={{ padding: "6px 10px", fontFamily: "monospace", fontSize: 12 }}
          />
        </label>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button type="button" disabled={loading} onClick={applyFilters} style={{ padding: "8px 16px" }}>
            Apply filters
          </button>
          <button
            type="button"
            disabled={loading}
            onClick={() => void clearFiltersAndRefetch()}
            style={{ padding: "8px 16px" }}
          >
            Clear
          </button>
        </div>
      </section>

      {loading && events.length === 0 && (
        <p style={{ marginTop: 24 }}>Loading events…</p>
      )}

      {!loading && events.length === 0 && !err && (
        <p style={{ marginTop: 24, color: "#666" }}>
          {filtersActive
            ? "No events match the current filters."
            : "No audit events recorded yet."}
        </p>
      )}

      {!loading && events.length > 0 && (
        <>
          <div
            style={{
              marginTop: 20,
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 12,
              fontSize: 14,
              color: "#555",
            }}
          >
            <span>
              {total > 0
                ? `Page ${page + 1} of ${totalPages} · ${total} events`
                : "0 events"}
            </span>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                type="button"
                disabled={!canPrev}
                onClick={() => fetchPage(page - 1)}
              >
                Previous
              </button>
              <button
                type="button"
                disabled={!canNext || (page + 1) * PAGE_SIZE >= total}
                onClick={() => fetchPage(page + 1)}
              >
                Next
              </button>
            </div>
          </div>

          <div style={{ overflowX: "auto", marginTop: 12 }}>
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
                <tr style={{ textAlign: "left", background: "#fafafa", borderBottom: "1px solid #e0e0e0" }}>
                  <th style={{ padding: 10 }}>When (UTC/local)</th>
                  <th style={{ padding: 10 }}>Action</th>
                  <th style={{ padding: 10 }}>Result</th>
                  <th style={{ padding: 10 }}>User</th>
                  <th style={{ padding: 10 }}>Document ID</th>
                  <th style={{ padding: 10 }}>IP</th>
                  <th style={{ padding: 10 }}>Reason / meta</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => {
                  const ok = e.result?.toUpperCase() === "SUCCESS";
                  return (
                    <tr key={e.id} style={{ borderBottom: "1px solid #eee" }}>
                      <td style={{ padding: 10, whiteSpace: "nowrap" }}>
                        {new Date(e.timestamp).toLocaleString()}
                      </td>
                      <td style={{ padding: 10 }}>{formatAction(e.action)}</td>
                      <td style={{ padding: 10 }}>
                        <span
                          style={{
                            fontWeight: 600,
                            color: ok ? "#1b5e20" : "#b71c1c",
                          }}
                        >
                          {e.result?.toUpperCase()}
                        </span>
                      </td>
                      <td
                        style={{ padding: 10, maxWidth: 200, verticalAlign: "top" }}
                        title={[e.username, e.userId].filter(Boolean).join(" · ") || ""}
                      >
                        {e.username ? (
                          <div style={{ fontWeight: 600, marginBottom: e.userId ? 4 : 0 }}>{e.username}</div>
                        ) : null}
                        <div
                          style={{
                            fontFamily: "monospace",
                            fontSize: 11,
                            wordBreak: "break-all",
                            color: "#555",
                          }}
                        >
                          {e.userId ?? (e.username ? "" : "—")}
                        </div>
                      </td>
                      <td style={{ padding: 10, fontFamily: "monospace", fontSize: 11, maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis" }} title={e.documentId ?? ""}>
                        {e.documentId ?? "—"}
                      </td>
                      <td style={{ padding: 10 }}>{e.ip ?? "—"}</td>
                      <td style={{ padding: 10, maxWidth: 280, wordBreak: "break-word", color: "#444" }}>
                        {e.reason}
                        {e.metadata && (
                          <pre style={{ margin: "6px 0 0", fontSize: 10, whiteSpace: "pre-wrap" }}>
                            {e.metadata.length > 400 ? `${e.metadata.slice(0, 400)}…` : e.metadata}
                          </pre>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
};
