#!/usr/bin/env bash
# File: tools/nix/pki_gen.sh
# Purpose: Generate a lab Root CA, Intermediate CA, and Server/Client certs for testing.
# Usage:
#   ./tools/nix/pki_gen.sh --cn test.example.com --out ./out-pki
#
# Outputs:
#   out-pki/root/ca.crt, ca.key
#   out-pki/int/ca.crt, ca.key
#   out-pki/server/server.crt, server.key, server.fullchain.crt
#   out-pki/client/client.crt, client.key (optional)

set -euo pipefail

CN="test.example.com"
OUT="./out-pki"
MAKE_CLIENT="false"
DAYS_ROOT=3650
DAYS_INT=3650
DAYS_LEAF=825

while [ $# -gt 0 ]; do
  case "$1" in
    --cn) CN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --client) MAKE_CLIENT="true"; shift ;;
    --days-root) DAYS_ROOT="$2"; shift 2 ;;
    --days-int) DAYS_INT="$2"; shift 2 ;;
    --days-leaf) DAYS_LEAF="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--cn <dns_name>] [--out <dir>] [--client] [--days-root N] [--days-int N] [--days-leaf N]"
      exit 0
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$OUT/root" "$OUT/int" "$OUT/server" "$OUT/client"

echo "[1/7] Generating Root CA key..."
openssl genrsa -out "$OUT/root/ca.key" 4096 >/dev/null 2>&1

echo "[2/7] Generating Root CA certificate..."
openssl req -x509 -new -nodes -key "$OUT/root/ca.key" \
  -sha256 -days "$DAYS_ROOT" -subj "/CN=Horacio Lab Root CA" \
  -out "$OUT/root/ca.crt" >/dev/null 2>&1

echo "[3/7] Generating Intermediate CA key..."
openssl genrsa -out "$OUT/int/ca.key" 4096 >/dev/null 2>&1

echo "[4/7] Generating Intermediate CA CSR..."
openssl req -new -key "$OUT/int/ca.key" \
  -subj "/CN=Horacio Lab Intermediate CA" \
  -out "$OUT/int/ca.csr" >/dev/null 2>&1

cat > "$OUT/int/int_ca_ext.cnf" <<EOF
basicConstraints=CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

echo "[5/7] Signing Intermediate CA with Root..."
openssl x509 -req -in "$OUT/int/ca.csr" \
  -CA "$OUT/root/ca.crt" -CAkey "$OUT/root/ca.key" -CAcreateserial \
  -out "$OUT/int/ca.crt" -days "$DAYS_INT" -sha256 \
  -extfile "$OUT/int/int_ca_ext.cnf" >/dev/null 2>&1

echo "[6/7] Generating Server key + CSR for CN=$CN ..."
openssl genrsa -out "$OUT/server/server.key" 2048 >/dev/null 2>&1
openssl req -new -key "$OUT/server/server.key" \
  -subj "/CN=$CN" \
  -out "$OUT/server/server.csr" >/dev/null 2>&1

cat > "$OUT/server/server_ext.cnf" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$CN
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

echo "[7/7] Signing Server certificate with Intermediate..."
openssl x509 -req -in "$OUT/server/server.csr" \
  -CA "$OUT/int/ca.crt" -CAkey "$OUT/int/ca.key" -CAcreateserial \
  -out "$OUT/server/server.crt" -days "$DAYS_LEAF" -sha256 \
  -extfile "$OUT/server/server_ext.cnf" >/dev/null 2>&1

cat "$OUT/server/server.crt" "$OUT/int/ca.crt" > "$OUT/server/server.fullchain.crt"

if [ "$MAKE_CLIENT" = "true" ]; then
  echo "[extra] Generating Client key + CSR..."
  openssl genrsa -out "$OUT/client/client.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$OUT/client/client.key" \
    -subj "/CN=Horacio Lab Client" \
    -out "$OUT/client/client.csr" >/dev/null 2>&1

  cat > "$OUT/client/client_ext.cnf" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

  echo "[extra] Signing Client certificate with Intermediate..."
  openssl x509 -req -in "$OUT/client/client.csr" \
    -CA "$OUT/int/ca.crt" -CAkey "$OUT/int/ca.key" -CAcreateserial \
    -out "$OUT/client/client.crt" -days "$DAYS_LEAF" -sha256 \
    -extfile "$OUT/client/client_ext.cnf" >/dev/null 2>&1
fi

echo
echo "Done. Output directory: $OUT"
echo "Root CA:         $OUT/root/ca.crt"
echo "Intermediate CA: $OUT/int/ca.crt"
echo "Server cert:     $OUT/server/server.crt"
echo "Server chain:    $OUT/server/server.fullchain.crt"
if [ "$MAKE_CLIENT" = "true" ]; then
  echo "Client cert:     $OUT/client/client.crt"
fi
