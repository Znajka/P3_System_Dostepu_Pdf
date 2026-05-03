/**
 * API client service for Spring Boot backend and FastAPI microservice.
 */

import axios, { AxiosInstance, AxiosError } from "axios";

const SPRING_BOOT_BASE_URL = process.env.REACT_APP_SPRING_BOOT_URL || "http://localhost:8080";
const FASTAPI_BASE_URL = process.env.REACT_APP_FASTAPI_URL || "https://localhost:8443";

class ApiClient {
  private springBootClient: AxiosInstance;
  private fastApiClient: AxiosInstance;

  constructor() {
    // Spring Boot client (HTTP, session-based auth)
    this.springBootClient = axios.create({
      baseURL: SPRING_BOOT_BASE_URL,
      timeout: 30000,
      headers: {
        "Content-Type": "application/json",
      },
      withCredentials: true, // Include session cookies
    });

    // FastAPI client (HTTPS, token-based auth)
    this.fastApiClient = axios.create({
      baseURL: FASTAPI_BASE_URL,
      timeout: 60000, // Longer timeout for streaming
      headers: {
        "Content-Type": "application/json",
      },
      withCredentials: false,
    });

    // Add token to FastAPI requests
    this.fastApiClient.interceptors.request.use((config) => {
      const token = localStorage.getItem("accessToken");
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });
  }

  /**
   * Request open-ticket from Spring Boot.
   * Returns JWT ticket valid for 60 seconds.
   */
  async getOpenTicket(documentId: string): Promise<string> {
    try {
      const response = await this.springBootClient.get(
        `/api/documents/${documentId}/open-ticket`
      );
      const data = response.data as any;
      return data.ticket;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get document status from Spring Boot.
   */
  async getDocumentStatus(documentId: string) {
    try {
      const response = await this.springBootClient.get(
        `/api/documents/${documentId}/status`
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Stream decrypted PDF from FastAPI using ticket.
   * Returns ArrayBuffer of plaintext PDF bytes.
   */
  async streamDocumentPdf(
    ticket: string,
    dek: string,
    nonce: string,
    tag: string,
    chunkSize: number = 65536
  ): Promise<ArrayBuffer> {
    try {
      const response = await this.fastApiClient.get(
        `/stream/${ticket}`,
        {
          headers: {
            "X-DEK": dek,
            "X-Nonce": nonce,
            "X-Tag": tag,
            "X-Chunk-Size": chunkSize.toString(),
          },
          responseType: "arraybuffer",
          timeout: 120000, // Allow up to 2 minutes for large files
        }
      );

      // Validate security headers
      this.validateSecurityHeaders(response.headers);

      return response.data as ArrayBuffer;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get encryption metadata for a document from Spring Boot.
   * Spring Boot returns DEK (wrapped), nonce, tag from DB.
   * In production: Spring Boot unwraps DEK via KMS and returns plaintext DEK.
   */
  async getEncryptionMetadata(documentId: string): Promise<EncryptionMetadata> {
    try {
      const response = await this.springBootClient.get(
        `/api/internal/documents/${documentId}/encryption-metadata`
      );
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * List documents accessible to user.
   */
  async listDocuments(limit: number = 20, offset: number = 0) {
    try {
      const response = await this.springBootClient.get("/api/documents", {
        params: { limit, offset },
      });
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Validate security headers in response.
   */
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

  /**
   * Handle API errors.
   */
  private handleError(error: any): Error {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError;
      const message = (axiosError.response?.data as any)?.error?.message || error.message;
      return new Error(`API Error: ${message}`);
    }
    return error instanceof Error ? error : new Error("Unknown error");
  }

  /**
   * Set authorization token.
   */
  setAuthToken(token: string): void {
    localStorage.setItem("accessToken", token);
    this.springBootClient.defaults.headers.common["Authorization"] = `Bearer ${token}`;
  }

  /**
   * Clear authorization token.
   */
  clearAuthToken(): void {
    localStorage.removeItem("accessToken");
    delete this.springBootClient.defaults.headers.common["Authorization"];
  }
}

// Export singleton
export const apiClient = new ApiClient();