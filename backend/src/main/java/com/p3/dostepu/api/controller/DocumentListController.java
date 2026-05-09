package com.p3.dostepu.api.controller;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.p3.dostepu.api.dto.DocumentSummaryResponse;
import com.p3.dostepu.application.util.AccessShareStatus;
import com.p3.dostepu.application.util.DocumentTitles;
import com.p3.dostepu.domain.entity.Document;
import com.p3.dostepu.domain.repository.AccessGrantRepository;
import com.p3.dostepu.domain.repository.DocumentRepository;
import com.p3.dostepu.security.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/documents")
@RequiredArgsConstructor
public class DocumentListController {

  private final DocumentRepository documentRepository;
  private final AccessGrantRepository accessGrantRepository;

  @GetMapping
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<List<DocumentSummaryResponse>> listDocuments(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size,
      @RequestParam(defaultValue = "accessible") String scope) {

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
    UUID userId = userDetails.getUserId();

    int pageSize = Math.min(Math.max(size, 1), 100);
    ZonedDateTime now = ZonedDateTime.now();
    var paging = PageRequest.of(Math.max(page, 0), pageSize,
        Sort.by(Sort.Direction.DESC, "createdAt"));

    String mode = scope == null ? "accessible" : scope.trim().toLowerCase();
    Page<Document> docs =
        switch (mode) {
          case "owned" -> documentRepository.findOwnedByUser(userId, paging);
          case "shared" -> documentRepository.findSharedWithUser(userId, paging);
          default -> documentRepository.findAccessibleForUser(userId, now, paging);
        };

    List<DocumentSummaryResponse> body = docs.getContent().stream()
        .map(d -> {
          boolean viewerIsOwner = d.getOwner().getId().equals(userId);
          String title = viewerIsOwner ? d.getTitle()
              : DocumentTitles.maskedForNonOwner(d.getId());
          DocumentSummaryResponse.DocumentSummaryResponseBuilder b =
              DocumentSummaryResponse.builder()
                  .documentId(d.getId())
                  .title(title)
                  .ownerId(d.getOwner().getId())
                  .createdAt(d.getCreatedAt());
          if ("shared".equals(mode)) {
            accessGrantRepository
                .findFirstByDocument_IdAndGranteeUser_IdAndRevokedFalseOrderByCreatedAtDesc(
                    d.getId(), userId)
                .ifPresent(g -> b.grantId(g.getId())
                    .validFrom(g.getValidFrom())
                    .expiresAt(g.getExpiresAt())
                    .shareStatus(AccessShareStatus.forGrant(g, now)));
          }
          return b.build();
        })
        .collect(Collectors.toList());

    return ResponseEntity.ok(body);
  }
}
