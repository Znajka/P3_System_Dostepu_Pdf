package com.p3.dostepu.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Serves the bundled React SPA so the same origin (e.g. :8080) can show login and UI.
 * API routes live under /api; static assets under /assets come from classpath:/static/.
 */
@Controller
public class SpaForwardingController {

  @GetMapping(value = { "/", "/login", "/dashboard" })
  public String spaTopLevel() {
    return "forward:/index.html";
  }

  /**
   * Viewer route: /documents/&lt;uuid&gt; (matches React Router).
   */
  @GetMapping("/documents/{documentId}")
  public String spaDocument() {
    return "forward:/index.html";
  }
}
