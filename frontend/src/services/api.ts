/**
 * API client service for Spring Boot backend and FastAPI microservice.
 */

import axios, { AxiosInstance, AxiosError } from "axios";

const SPRING_BOOT_BASE_URL = process.env.REACT_APP_SPRING_BOOT_URL ?? "";
const FASTAPI_BASE_URL = process.env.REACT_APP_FASTAPI_URL ?? "";

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
}

export interface EncryptionMetadata {
  dek: string;
  nonce: string;
  tag: string;
  algorithm?: string;
}

class ApiClient {
  private springBootClient: AxiosInstance;
  private fastApiClient: AxiosInstance;

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

    const fastBase =
      FASTAPI_BASE_URL.length > 0
        ? FASTAPI_BASE_URL
        : typeof window !== "undefined"
          ? ""
          : "http://localhost:8443";
    this.fastApiClient = axios.create({
      baseURL: fastBase,
      timeout: 120000,
      headers: {
        "Content-Type": "application/json",
      },
      withCredentials: false,
    });

    const bearer = (): string | null => {
      if (typeof window === "undefined") return null;
      return localStorage.getItem("accessToken");
    };

    this.springBootClient.interceptors.request.use((config) => {
      const token = bearer();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    this.fastApiClient.interceptors.request.use((config) => {
      const token = bearer();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
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

  async getDocumentStatus(documentId: string): Promise<any> {
    const response = await this.springBootClient.get(
      `/api/documents/${documentId}/status`
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
    const encTicket = encodeURIComponent(ticket);
    const response = await this.fastApiClient.get(
      `/stream/${encTicket}`,
      {
        headers: {
          "X-DEK": dek,
          "X-Nonce": nonce,
          "X-Tag": tag,
          "X-Chunk-Size": chunkSize.toString(),
        },
        responseType: "arraybuffer",
        timeout: 120000,
      }
    );
    this.validateSecurityHeaders(response.headers);
    return response.data as ArrayBuffer;
  }

  async getEncryptionMetadata(documentId: string): Promise<EncryptionMetadata> {
    const response = await this.springBootClient.get(
      `/api/internal/documents/${documentId}/encryption-metadata`
    );
    return response.data as EncryptionMetadata;
  }

  async listDocuments(page: number = 0, size: number = 20): Promise<DocumentSummary[]> {
    const response = await this.springBootClient.get("/api/documents", {
      params: { page, size },
    });
    const rows = response.data as any[];
    return (rows || []).map((d) => ({
      documentId: d.documentId,
      title: d.title,
      ownerId: d.ownerId,
      createdAt: d.createdAt,
    }));
  }

  async uploadPdf(file: File, title: string, description?: string): Promise<{ documentId: string }> {
    const fd = new FormData();
    fd.append("title", title);
    if (description) {
      fd.append("description", description);
    }
    fd.append("file", file);
    const response = await this.springBootClient.post("/api/documents", fd, {
      timeout: 120000,
    });
    const data = response.data as { documentId?: string };
    if (!data.documentId) {
      throw new Error("Upload response missing documentId");
    }
    return { documentId: data.documentId };
  }

  async grantAccess(
    documentId: string,
    body: {
      granteeUserId?: string;
      granteeUsername?: string;
      granteeEmail?: string;
      expiresAt: string;
      note?: string;
    }
  ): Promise<void> {
    await this.springBootClient.post(`/api/documents/${documentId}/grant`, body);
  }

  async revokeAccess(
    documentId: string,
    body: {
      granteeUserId?: string;
      granteeUsername?: string;
      granteeEmail?: string;
      reason?: string;
    }
  ): Promise<void> {
    await this.springBootClient.post(`/api/documents/${documentId}/revoke`, body);
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
      const msg =
        body?.error?.message ||
        body?.message ||
        axiosError.response?.statusText ||
        axiosError.message;
      return new Error(`API Error: ${msg}`);
    }
    return error instanceof Error ? error : new Error("Unknown error");
  }

  wrapError(fn: () => Promise<any>): Promise<any> {
    return fn().catch((e) => {
      throw this.handleError(e);
    });
  }

  setAuthToken(token: string): void {
    localStorage.setItem("accessToken", token);
    this.springBootClient.defaults.headers.common["Authorization"] = `Bearer ${token}`;
  }

  clearAuthToken(): void {
    localStorage.removeItem("accessToken");
    delete this.springBootClient.defaults.headers.common["Authorization"];
  }
}

export const apiClient = new ApiClient();
