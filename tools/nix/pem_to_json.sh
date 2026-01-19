\
#!/usr/bin/env bash
# File: tools/nix/pem_to_json.sh
# Purpose: Convert PEM file to a JSON-safe string by escaping newlines as \n.
# Usage: ./tools/nix/pem_to_json.sh path/to/cert.pem

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

# Read raw and convert CRLF/LF to literal \n sequences.
# Output is a single line suitable for JSON string values.
perl -0777 -pe 's/\r\n/\n/g; s/\n/\\n/g' "$pem_file"
echo
