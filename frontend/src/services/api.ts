/**
 * API client service for Spring Boot backend and FastAPI microservice.
 */

import axios, { AxiosInstance, AxiosError } from "axios";

const SPRING_BOOT_BASE_URL = process.env.REACT_APP_SPRING_BOOT_URL ?? "";

/** Same-tab login/logout does not fire `storage`; App listens for this to refresh auth state. */
function emitAccessTokenChanged(): void {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("p3-access-token-changed"));
  }
}

export interface LoginResponse {
  userId: string;
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  username: string;
  roles: string[];
}

export interface DocumentSummary {
  documentId: string;
  title: string;
  ownerId: string;
  createdAt: string;
  /** Filled when listing with scope=shared */
  grantId?: string;
  validFrom?: string;
  expiresAt?: string;
  shareStatus?: string;
}

export interface EncryptionMetadata {
  dek: string;
  nonce: string;
  tag: string;
  algorithm?: string;
}

/** Grant row returned to document owner/admin from GET /api/documents/{id}/status */
export interface DocumentGrantShare {
  grantId: string;
  granteeUserId: string;
  granteeUsername?: string | null;
  granteeEmail?: string | null;
  validFrom: string;
  expiresAt: string;
  revoked?: boolean | null;
  shareStatus: string;
}

export interface DocumentStatus {
  documentId: string;
  title?: string;
  ownerId?: string;
  createdAt?: string;
  accessible?: boolean;
  grants?: DocumentGrantShare[];
  locked?: boolean;
  access?: {
    grantId?: string;
    granteeUserId: string;
    validFrom: string;
    expiresAt: string;
    shareStatus?: string;
  };
}

export interface AccessEventEntry {
  id: string;
  timestamp: string;
  userId: string | null;
  username?: string | null;
  documentId: string | null;
  action: string;
  result: string;
  ip: string | null;
  reason: string | null;
  metadata: string | null;
}

export interface AccessEventLogPage {
  total: number;
  limit: number;
  offset: number;
  events: AccessEventEntry[];
}

class ApiClient {
  private springBootClient: AxiosInstance;

  constructor() {
    const springBase =
      SPRING_BOOT_BASE_URL.length > 0
        ? SPRING_BOOT_BASE_URL
        : typeof window !== "undefined"
          ? ""
          : "http://localhost:8080";
    this.springBootClient = axios.create({
      baseURL: springBase,
      timeout: 30000,
      headers: {
        "Content-Type": "application/json",
      },
    });

    const bearer = (): string | null => {
      if (typeof window === "undefined") return null;
      return localStorage.getItem("accessToken");
    };

    this.springBootClient.interceptors.request.use((config) => {
      const token = bearer();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      } else if (config.headers) {
        const h = config.headers;
        if (typeof h.delete === "function") {
          h.delete("Authorization");
        } else {
          delete (h as Record<string, unknown>)["Authorization"];
        }
      }
      // Instance default is application/json — breaks multipart uploads (415).
      if (config.data instanceof FormData && config.headers) {
        const h = config.headers;
        if (typeof h.delete === "function") {
          h.delete("Content-Type");
        } else {
          delete (h as Record<string, unknown>)["Content-Type"];
        }
      }
      return config;
    });

    const t = bearer();
    if (t) {
      this.springBootClient.defaults.headers.common["Authorization"] = `Bearer ${t}`;
    }
  }

  async login(username: string, password: string): Promise<LoginResponse> {
    const response = await this.springBootClient.post("/api/auth/login", {
      username,
      password,
    });
    const data = response.data as any;
    return {
      userId: data.userId,
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
      tokenType: data.tokenType,
      username: data.username,
      roles: data.roles ?? [],
    };
  }

  async getOpenTicket(documentId: string): Promise<string> {
    const response = await this.springBootClient.get(
      `/api/documents/${documentId}/open-ticket`
    );
    const data = response.data as { ticket?: string };
    const t = data.ticket;
    if (!t) {
      throw new Error("Missing ticket in open-ticket response");
    }
    return t;
  }

  async getDocumentStatus(documentId: string): Promise<DocumentStatus> {
    const response = await this.springBootClient.get<DocumentStatus>(
      `/api/documents/${documentId}/status`
    );
    return response.data;
  }

  async getAccessEventLogs(params?: {
    limit?: number;
    offset?: number;
    documentId?: string;
    userId?: string;
    action?: string;
    result?: string;
    from?: string;
    to?: string;
  }): Promise<AccessEventLogPage> {
    const response = await this.springBootClient.get<AccessEventLogPage>(
      "/api/logs/access-events",
      { params: params ?? {} }
    );
    return response.data;
  }

  async streamDocumentPdf(
    ticket: string,
    dek: string,
    nonce: string,
    tag: string,
    chunkSize: number = 65536
  ): Promise<ArrayBuffer> {
    // Ticket in header: long JWT in query can be truncated/decoded badly (401 from FastAPI).
    const response = await this.springBootClient.get("/api/stream/pdf", {
      headers: {
        "X-Document-Stream-Ticket": ticket,
        "X-DEK": dek,
        "X-Nonce": nonce,
        "X-Tag": tag,
        "X-Chunk-Size": chunkSize.toString(),
      },
      responseType: "arraybuffer",
      timeout: 120000,
    });
    this.validateSecurityHeaders(response.headers);
    return response.data as ArrayBuffer;
  }

  async getEncryptionMetadata(documentId: string): Promise<EncryptionMetadata> {
    const response = await this.springBootClient.get(
      `/api/internal/documents/${documentId}/encryption-metadata`
    );
    return response.data as EncryptionMetadata;
  }

  async listDocuments(
    page: number = 0,
    size: number = 20,
    scope: "accessible" | "owned" | "shared" = "accessible"
  ): Promise<DocumentSummary[]> {
    const response = await this.springBootClient.get("/api/documents", {
      params: { page, size, scope },
    });
    const rows = response.data as any[];
    return (rows || []).map((d) => ({
      documentId:
        typeof d.documentId === "string" ? d.documentId : String(d.documentId),
      title: d.title,
      ownerId:
        typeof d.ownerId === "string" ? d.ownerId : String(d.ownerId ?? ""),
      createdAt: d.createdAt,
      grantId:
        d.grantId !== undefined && d.grantId !== null ? String(d.grantId) : undefined,
      validFrom: d.validFrom,
      expiresAt: d.expiresAt,
      shareStatus: d.shareStatus,
    }));
  }

  async uploadPdf(file: File, description?: string): Promise<{ documentId: string }> {
    const fd = new FormData();
    if (description) {
      fd.append("description", description);
    }
    fd.append("file", file);
    try {
      const response = await this.springBootClient.post("/api/documents", fd, {
        timeout: 120000,
      });
      const data = response.data as { documentId?: string };
      if (!data.documentId) {
        throw new Error("Upload response missing documentId");
      }
      return { documentId: data.documentId };
    } catch (e) {
      throw this.handleError(e);
    }
  }

  async grantAccess(
    documentId: string,
    body: {
      granteeUsername: string;
      expiresAt: string;
      validFrom?: string;
      note?: string;
    }
  ): Promise<void> {
    await this.springBootClient.post(`/api/documents/${documentId}/grant`, body);
  }

  async revokeAccess(
    documentId: string,
    body: {
      granteeUsername: string;
      reason?: string;
    }
  ): Promise<void> {
    await this.springBootClient.post(`/api/documents/${documentId}/revoke`, body);
  }

  /** Remove grant row; if still active, access is revoked first (audit). */
  async deleteGrant(documentId: string, grantId: string): Promise<void> {
    try {
      await this.springBootClient.delete(
        `/api/documents/${documentId}/grants/${grantId}`
      );
    } catch (e) {
      throw this.handleError(e);
    }
  }

  private validateSecurityHeaders(headers: Record<string, any>): void {
    const cacheControl = headers["cache-control"] || "";
    const contentType = headers["content-type"] || "";
    if (!cacheControl.includes("no-store")) {
      console.warn("Warning: Cache-Control header missing no-store");
    }
    if (!contentType.includes("application/pdf")) {
      console.warn("Warning: Unexpected content-type:", contentType);
    }
  }

  private handleError(error: any): Error {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError;
      const body = axiosError.response?.data as any;
      const detail = body?.detail;
      const detailStr =
        typeof detail === "string"
          ? detail
          : Array.isArray(detail)
            ? detail.map((d: any) => d?.msg || String(d)).join("; ")
            : "";
      const msg =
        body?.error?.message ||
        detailStr ||
        body?.message ||
        axiosError.response?.statusText ||
        axiosError.message;
      return new Error(msg || "Request failed");
    }
    return error instanceof Error ? error : new Error("Unknown error");
  }

  wrapError(fn: () => Promise<any>): Promise<any> {
    return fn().catch((e) => {
      throw this.handleError(e);
    });
  }

  /**
   * Sync axios defaults from localStorage without emitting auth events (for App.tsx sync).
   */
  applyAuthSnapshotFromStorage(): void {
    if (typeof window === "undefined") {
      return;
    }
    const t = localStorage.getItem("accessToken");
    if (t) {
      this.springBootClient.defaults.headers.common["Authorization"] = `Bearer ${t}`;
    } else {
      delete this.springBootClient.defaults.headers.common["Authorization"];
    }
  }

  setAuthToken(token: string): void {
    const prev =
      typeof window !== "undefined" ? localStorage.getItem("accessToken") : null;
    localStorage.setItem("accessToken", token);
    this.springBootClient.defaults.headers.common["Authorization"] = `Bearer ${token}`;
    if (prev !== token) {
      emitAccessTokenChanged();
    }
  }

  clearAuthToken(): void {
    const prev =
      typeof window !== "undefined" ? localStorage.getItem("accessToken") : null;
    localStorage.removeItem("accessToken");
    delete this.springBootClient.defaults.headers.common["Authorization"];
    if (prev !== null) {
      emitAccessTokenChanged();
    }
  }
}

export const apiClient = new ApiClient();
