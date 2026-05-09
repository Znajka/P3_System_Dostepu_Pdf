package com.p3.dostepu.application.util;

import java.nio.file.Paths;
import java.util.UUID;

/**
 * Stored title is the original upload filename (sanitized).
 * Non-owners receive a masked label that does not reveal the filename.
 */
public final class DocumentTitles {

  private DocumentTitles() {}

  public static String fromOriginalFilename(String originalFilename) {
    if (originalFilename == null || originalFilename.isBlank()) {
      return "document.pdf";
    }
    String name = Paths.get(originalFilename).getFileName().toString();
    if (name.isBlank()) {
      return "document.pdf";
    }
    if (name.length() > 255) {
      name = name.substring(0, 255);
    }
    return name;
  }

  /** Shown to grantees and to admins who are not the document owner. */
  public static String maskedForNonOwner(UUID documentId) {
    String hex = documentId.toString().replace("-", "");
    String suffix = hex.length() >= 8 ? hex.substring(0, 8) : hex;
    return "Document · " + suffix;
  }
}
