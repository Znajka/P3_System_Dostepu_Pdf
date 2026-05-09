<#
 Upload smoke test against local Spring Boot (default http://localhost:8080 ).
 Docker: compose up --build , then wait for healthcheck.

 Usage:
   .\scripts\smoke-upload.ps1
   .\scripts\smoke-upload.ps1 -PdfPath "D:\downloads\my.pdf"
   .\scripts\smoke-upload.ps1 -BaseUrl "http://localhost:8080" -Username "alice" -Password "alice123"
#>
param(
  [string] $PdfPath = "",
  [string] $Title = "Smoke upload",
  [string] $BaseUrl = "http://localhost:8080",
  [string] $Username = "alice",
  [string] $Password = "alice123"
)

$ErrorActionPreference = "Stop"

# Minimal single-page PDF (valid structure; xref matches).
$b64 = "JVBERi0xLjQKMSAwIG9iago8PC9UeXBlL0NhdGFsb2cvUGFnZXMgMiAwIFI+PgplbmRvYmoKMiAwIG9iago8PC9UeXBlL1BhZ2VzL0tpZHNbMyAwIFJdL0NvdW50IDE+PgplbmRvYmoKMyAwIG9iago8PC9UeXBlL1BhZ2UvTWVkaWFCb3hbMCAwIDYxMiA3OTJdL1BhcmVudCAyIDAgUj4+CmVuZG9iagp4cmVmCjAgNAowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwMDkgMDAwMDAgbiAKMDAwMDAwMDA1MiAwMDAwMCBuIAowMDAwMDAwMTAxIDAwMDAwIG4gCnRyYWlsZXIKPDwvU2l6ZSA0L1Jvb3QgMSAwIFI+CgpzdGFydHhyZWYKMTc4CiUlRU9G"

if (-not $PdfPath) {
  $PdfPath = Join-Path ([IO.Path]::GetTempPath()) "p3-smoke-minimal.pdf"
  [IO.File]::WriteAllBytes($PdfPath, [Convert]::FromBase64String($b64))
  Write-Host "Using embedded minimal PDF: $PdfPath"
} elseif (-not (Test-Path -LiteralPath $PdfPath)) {
  throw "File not found: $PdfPath"
}

$loginUri = "$BaseUrl/api/auth/login"
$uploadUri = "$BaseUrl/api/documents"

$bodyObj = @{ username = $Username; password = $Password } | ConvertTo-Json

try {
  $login = Invoke-RestMethod -Method Post -Uri $loginUri -ContentType "application/json; charset=utf-8" -Body $bodyObj
} catch {
  Write-Error "Login failed (${loginUri}). Is the stack running? $($_.Exception.Message)"
  exit 1
}

$token = $login.accessToken
if (-not $token) {
  Write-Error "Login response missing accessToken"
  exit 1
}

$pdfFull = Resolve-Path $PdfPath

# curl.exe sets multipart boundary correctly on Windows (Invoke-RestMethod multipart is clumsy).
$args = @(
  "-s", "-S",
  "-X", "POST", $uploadUri,
  "-H", "Authorization: Bearer $token",
  "-F", "title=$Title",
  "-F", "file=@$pdfFull;type=application/pdf"
)

& curl.exe @args

if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}
