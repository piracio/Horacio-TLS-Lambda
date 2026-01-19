\
# File: tools/powershell/pki_gen.ps1
# Purpose: Generate a lab Root CA, Intermediate CA, and Server/Client certs for testing.
# Usage:
#   pwsh ./tools/powershell/pki_gen.ps1 -CN test.example.com -OutDir ./out-pki -MakeClient
#
# Requirements:
#   - OpenSSL available in PATH (openssl.exe)

param(
  [string] $CN = "test.example.com",
  [string] $OutDir = "./out-pki",
  [switch] $MakeClient,
  [int] $DaysRoot = 3650,
  [int] $DaysInt = 3650,
  [int] $DaysLeaf = 825
)

function Exec([string]$cmd) {
  $p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cmd -NoNewWindow -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "Command failed ($($p.ExitCode)): $cmd" }
}

New-Item -ItemType Directory -Force -Path (Join-Path $OutDir "root") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $OutDir "int") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $OutDir "server") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $OutDir "client") | Out-Null

$rootKey = Join-Path $OutDir "root/ca.key"
$rootCrt = Join-Path $OutDir "root/ca.crt"
$intKey  = Join-Path $OutDir "int/ca.key"
$intCsr  = Join-Path $OutDir "int/ca.csr"
$intCrt  = Join-Path $OutDir "int/ca.crt"
$serverKey = Join-Path $OutDir "server/server.key"
$serverCsr = Join-Path $OutDir "server/server.csr"
$serverCrt = Join-Path $OutDir "server/server.crt"
$serverFullchain = Join-Path $OutDir "server/server.fullchain.crt"

Write-Host "[1/7] Generating Root CA key..."
Exec "openssl genrsa -out `"$rootKey`" 4096"

Write-Host "[2/7] Generating Root CA certificate..."
Exec "openssl req -x509 -new -nodes -key `"$rootKey`" -sha256 -days $DaysRoot -subj `"/CN=Horacio Lab Root CA`" -out `"$rootCrt`""

Write-Host "[3/7] Generating Intermediate CA key..."
Exec "openssl genrsa -out `"$intKey`" 4096"

Write-Host "[4/7] Generating Intermediate CA CSR..."
Exec "openssl req -new -key `"$intKey`" -subj `"/CN=Horacio Lab Intermediate CA`" -out `"$intCsr`""

$intExt = Join-Path $OutDir "int/int_ca_ext.cnf"
@"
basicConstraints=CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"@ | Set-Content -NoNewline -Encoding ascii $intExt

Write-Host "[5/7] Signing Intermediate CA with Root..."
Exec "openssl x509 -req -in `"$intCsr`" -CA `"$rootCrt`" -CAkey `"$rootKey`" -CAcreateserial -out `"$intCrt`" -days $DaysInt -sha256 -extfile `"$intExt`""

Write-Host "[6/7] Generating Server key + CSR for CN=$CN ..."
Exec "openssl genrsa -out `"$serverKey`" 2048"
Exec "openssl req -new -key `"$serverKey`" -subj `"/CN=$CN`" -out `"$serverCsr`""

$serverExt = Join-Path $OutDir "server/server_ext.cnf"
@"
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$CN
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"@ | Set-Content -NoNewline -Encoding ascii $serverExt

Write-Host "[7/7] Signing Server certificate with Intermediate..."
Exec "openssl x509 -req -in `"$serverCsr`" -CA `"$intCrt`" -CAkey `"$intKey`" -CAcreateserial -out `"$serverCrt`" -days $DaysLeaf -sha256 -extfile `"$serverExt`""

# Fullchain
(Get-Content -Raw $serverCrt) + (Get-Content -Raw $intCrt) | Set-Content -NoNewline $serverFullchain

if ($MakeClient.IsPresent) {
  $clientKey = Join-Path $OutDir "client/client.key"
  $clientCsr = Join-Path $OutDir "client/client.csr"
  $clientCrt = Join-Path $OutDir "client/client.crt"

  Write-Host "[extra] Generating Client key + CSR..."
  Exec "openssl genrsa -out `"$clientKey`" 2048"
  Exec "openssl req -new -key `"$clientKey`" -subj `"/CN=Horacio Lab Client`" -out `"$clientCsr`""

  $clientExt = Join-Path $OutDir "client/client_ext.cnf"
  @"
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"@ | Set-Content -NoNewline -Encoding ascii $clientExt

  Write-Host "[extra] Signing Client certificate with Intermediate..."
  Exec "openssl x509 -req -in `"$clientCsr`" -CA `"$intCrt`" -CAkey `"$intKey`" -CAcreateserial -out `"$clientCrt`" -days $DaysLeaf -sha256 -extfile `"$clientExt`""
}

Write-Host ""
Write-Host "Done. Output directory: $OutDir"
Write-Host "Root CA:         $rootCrt"
Write-Host "Intermediate CA: $intCrt"
Write-Host "Server cert:     $serverCrt"
Write-Host "Server chain:    $serverFullchain"
if ($MakeClient.IsPresent) {
  Write-Host "Client cert:     $(Join-Path $OutDir "client/client.crt")"
}
