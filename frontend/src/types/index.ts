/**
 * TypeScript type definitions for P3 Dostepu frontend.
 */

export interface Document {
  documentId: string;
  title: string;
  ownerId: string;
  createdAt: string;
  accessible: boolean;
  access?: {
    granteeUserId: string;
    expiresAt: string;
  };
}

export interface OpenTicketResponse {
  ticket: string;
  ticketId: string;
  expiresAt: string;
  issuedAt: string;
  usage: {
    singleUse: boolean;
    aud: string;
    documentId: string;
    userId: string;
  };
}

export interface EncryptionMetadata {
  dek: string;      // Base64-encoded DEK
  nonce: string;    // Base64-encoded nonce
  tag: string;      // Base64-encoded authentication tag
}

export interface StreamingError {
  code: string;
  message: string;
  details?: Record<string, any>;
}

export interface AuthContext {
  accessToken: string | null;
  userId: string | null;
  isAuthenticated: boolean;
  login: (token: string, userId: string) => void;
  logout: () => void;
}