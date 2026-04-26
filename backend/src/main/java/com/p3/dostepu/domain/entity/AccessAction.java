package com.p3.dostepu.domain.entity;

/**
 * Access action enumeration: types of security-relevant events logged in
 * ACCESS_EVENT_LOG table.
 */
public enum AccessAction {
  UPLOAD,
  GRANT,
  REVOKE,
  OPEN_ATTEMPT,
  STREAM_START,
  STREAM_END
}