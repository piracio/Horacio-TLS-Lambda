\
# File: tools/powershell/pem_to_base64.ps1
# Purpose: Base64-encode a PEM file as UTF-8 text.
# Usage: pwsh ./tools/powershell/pem_to_base64.ps1 -PemFile ./ca.pem

param(
  [Parameter(Mandatory=$true)]
  [string] $PemFile
)

if (-not (Test-Path -LiteralPath $PemFile)) {
  throw "File not found: $PemFile"
}

$pem = Get-Content -Raw -LiteralPath $PemFile
$bytes = [System.Text.Encoding]::UTF8.GetBytes($pem)
[Convert]::ToBase64String($bytes)
