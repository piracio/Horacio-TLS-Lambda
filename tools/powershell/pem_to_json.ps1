\
# File: tools/powershell/pem_to_json.ps1
# Purpose: Convert PEM file to a JSON-safe string by escaping newlines as \n.
# Usage: pwsh ./tools/powershell/pem_to_json.ps1 -PemFile ./ca.pem

param(
  [Parameter(Mandatory=$true)]
  [string] $PemFile
)

if (-not (Test-Path -LiteralPath $PemFile)) {
  throw "File not found: $PemFile"
}

$pem = Get-Content -Raw -LiteralPath $PemFile
# Normalize CRLF to LF then escape as \n
$pem = $pem -replace "`r`n", "`n"
$pem = $pem -replace "`n", "\n"
$pem
