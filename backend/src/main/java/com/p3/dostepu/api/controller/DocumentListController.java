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
import com.p3.dostepu.domain.entity.Document;
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

  @GetMapping
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<List<DocumentSummaryResponse>> listDocuments(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size) {

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    CustomUserDetails userDetails = (CustomUserDetails) auth.getPrincipal();
    UUID userId = userDetails.getUserId();

    int pageSize = Math.min(Math.max(size, 1), 100);
    Page<Document> docs = documentRepository.findAccessibleForUser(
        userId,
        ZonedDateTime.now(),
        PageRequest.of(Math.max(page, 0), pageSize,
            Sort.by(Sort.Direction.DESC, "createdAt")));

    List<DocumentSummaryResponse> body = docs.getContent().stream()
        .map(d -> DocumentSummaryResponse.builder()
            .documentId(d.getId())
            .title(d.getTitle())
            .ownerId(d.getOwner().getId())
            .createdAt(d.getCreatedAt())
            .build())
        .collect(Collectors.toList());

    return ResponseEntity.ok(body);
  }
}
