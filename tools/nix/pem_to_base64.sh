\
#!/usr/bin/env bash
# File: tools/nix/pem_to_base64.sh
# Purpose: Base64-encode a PEM file as UTF-8 text.
# Usage: ./tools/nix/pem_to_base64.sh path/to/cert.pem

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <pem_file>" >&2
  exit 2
fi

pem_file="$1"
if [ ! -f "$pem_file" ]; then
  echo "ERROR: File not found: $pem_file" >&2
  exit 1
fi

# -w0 works on GNU base64; macOS uses -b 0. Support both.
if base64 --help 2>/dev/null | grep -q -- '-w'; then
  base64 -w 0 "$pem_file"
else
  base64 -b 0 "$pem_file"
fi
echo
