# Tools

This folder contains helper scripts to support the Horacio-TLS-Lambda project.

## Layout

- `tools/nix/`        Shell scripts for macOS/Linux (bash/sh).
- `tools/powershell/` PowerShell scripts for Windows/macOS/Linux (pwsh).

## Prerequisites

- OpenSSL 1.1+ or 3.x available in `PATH` (`openssl version`).
- For PowerShell scripts, use PowerShell 7+ (`pwsh`).

## What’s included

- `pem_to_json.*` : Converts a PEM file to a JSON-safe single-line string (escapes newlines as `\n`).
- `pem_to_base64.*`: Base64-encodes a PEM file (UTF-8 text).
- `pki_gen.*`      : Generates a small lab PKI (Root CA, Intermediate CA, Server cert, optional Client cert).

## Notes

- These scripts are intended for **testing/lab use**. Do not use the generated CA to secure production systems.
- The PKI generator writes into `./out-pki/` by default.
