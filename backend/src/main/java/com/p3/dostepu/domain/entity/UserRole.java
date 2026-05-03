package com.p3.dostepu.domain.entity;

/**
 * Global user roles: ADMIN (full access), USER (default).
 * Document ownership is stored on {@link Document#getOwner()}, not as a role.
 */
public enum UserRole {
  ADMIN,
  USER
}