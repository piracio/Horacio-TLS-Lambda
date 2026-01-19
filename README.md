# Horacio-TLS-Lambda

**Horacio-TLS-Lambda** is an AWS Lambda function written in **.NET (net8.0)** that performs an HTTP/HTTPS request and produces a detailed timing breakdown.

It prints an **ASCII waterfall timeline (Gantt-like)** in CloudWatch logs and returns structured JSON including:

- DNS resolution time
- TCP connect time
- TLS handshake time (plus coarse internal TLS steps)
- TTFB (Time To First Byte) — raw and net
- Transfer time (download)
- Total request time
- TLS session details (protocol, cipher, ALPN, certificate details, SANs, chain status)
- Warnings when any phase exceeds **1 second**

---

## Makefile (macOS/Linux only)

This repository includes a `Makefile` intended for **macOS and Linux** users.

Windows users should run the commands directly using PowerShell (see the examples in this README).

Common targets:

```bash
make build
make run
make run URL=https://google.com
make run-online-soft URL=https://example.com
make run-online-strict URL=https://example.com
```

Base URL shortcuts (edit `URL_BASE` inside the Makefile):

```bash
make run-base-nocheck
make run-base-online-soft
make run-base-online-strict
```

---

## License

This project is licensed under **GPLv2**. See the `LICENSE` file.

---

## Features

### Timing breakdown
The Lambda measures the following phases:

- **DNS**: host resolution (`Dns.GetHostAddressesAsync`)
- **TCP**: connect to target IP/port (`Socket.ConnectAsync`)
- **TLS**: handshake using `SslStream.AuthenticateAsClientAsync` (HTTPS only)
- **TTFB raw**: time until response headers are received (includes DNS + TCP + TLS)
- **TTFB net**: `TTFB raw - (DNS + TCP + TLS)` (approximate server-side / upstream time)
- **Transfer**: time to read the full response body
- **Total**: full execution duration

### TLS validation modes
- **SystemTrust** (default): uses AWS Lambda runtime OS certificate store
- **CustomRootTrust**: when `caRootPem` is provided, TLS is validated strictly using the provided root CA bundle
- `intermediatePem` can be provided to help chain building if the server does not send intermediates correctly

### Waterfall visualization
CloudWatch logs include an ASCII timeline like:

```text
Waterfall (0 -> 245.12 ms)
DNS    |   #######                                                                     |     12.30 ms
TCP    |          ##########                                                           |     18.40 ms
TLS    |                    ###################                                        |     52.10 ms
TTFB   |                                       ############################            |    120.00 ms
XFER   |                                                                   #########   |     42.30 ms
TOTAL  |############################################################################## |    245.12 ms
```

### Warnings
If any phase exceeds **1000 ms**, the Lambda logs and returns warnings such as:

```text
WARNING: TLS handshake took 1240.55 ms (> 1000 ms).
```

---

## Requirements

- .NET SDK 8
- AWS CLI configured (`aws configure`)
- Amazon Lambda Tools

---

## Install Amazon Lambda Tools

Amazon Lambda Tools is a .NET Global Tool used to package and deploy Lambda functions.

Install:

```bash
dotnet tool install --global Amazon.Lambda.Tools
```

Verify:

```bash
dotnet lambda --help
```

If `dotnet lambda` is not found, ensure your .NET global tools directory is in your PATH.

Typical locations:
- Linux/macOS: `~/.dotnet/tools`
- Windows: `%USERPROFILE%\.dotnet\tools`

---

## Project structure

Recommended repo layout:

```text
Horacio-TLS-Lambda/
├── README.md
├── LICENSE
├── .gitignore
└── src/
    ├── Horacio-TLS-Lambda/
    │   ├── Horacio-TLS-Lambda.csproj
    │   ├── Function.cs
    │   ├── aws-lambda-tools-defaults.json
    │   └── Horacio-TLS-Lambda.sln
    └── Horacio-TLS-Lambda.Local/
        ├── Horacio-TLS-Lambda.Local.csproj
        └── Program.cs
```

---

## Build

From the repo root:

```bash
dotnet build -c Release
```

Or from the Lambda project directory:

```bash
cd src/Horacio-TLS-Lambda
dotnet build -c Release
```

---

## Deploy

From the Lambda project directory:

```bash
cd src/Horacio-TLS-Lambda
dotnet lambda deploy-function Horacio-TLS-Lambda
```

Notes:
- On first deploy, the tool may prompt you for AWS region, IAM role, etc.
- You can configure defaults using `aws-lambda-tools-defaults.json`.

---

## Invoke (CLI)

### Minimal input example

```bash
dotnet lambda invoke-function Horacio-TLS-Lambda --payload '{
  "url": "https://example.com"
}'
```

### Full input example (private CA / custom trust)

```bash
dotnet lambda invoke-function Horacio-TLS-Lambda --payload '{
  "url": "https://your-private-endpoint.example.local/api/health",
  "method": "GET",
  "timeoutMs": 15000,
  "caRootPem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "intermediatePem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
}'
```

Notes:
- The Lambda will auto-detect if the string is PEM vs Base64
- Base64 supports both DER certificates and full PEM text encoded as Base64

---

### Full input example (private CA using Base64)

If your CA bundle is hard to embed into JSON (because of line breaks), you can provide it as **Base64**:

```bash
dotnet lambda invoke-function Horacio-TLS-Lambda --payload '{
  "url": "https://your-private-endpoint.example.local/api/health",
  "method": "GET",
  "timeoutMs": 15000,
  "caRootPem": "<BASE64_ENCODED_CA_PEM_OR_DER>",
  "intermediatePem": "<BASE64_ENCODED_INTERMEDIATE_PEM_OR_DER>"
}'
```

---

## Input parameters

The Lambda input event supports:

| Field | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `url` | string | Yes | (none) | HTTP/HTTPS URL to query |
| `method` | string | No | `GET` | HTTP method |
| `timeoutMs` | int | No | `15000` | Timeout for the full request |
| `revocationMode` | string | No | `NoCheck` | Certificate revocation checking: `NoCheck`, `Online`, `Offline` |
| `revocationSoftFail` | bool | No | `true` | If `true`, do not fail TLS when revocation status cannot be verified (unknown/offline). Still fails if explicitly revoked. |
| `revocationMode` | string | No | `NoCheck` | Certificate revocation checking: `NoCheck`, `Online`, `Offline` |
| `caRootPem` | string | No | empty | Root CA bundle in PEM format (enables CustomRootTrust) |
| `intermediatePem` | string | No | empty | Intermediate certificates in PEM format |

Important notes:
- `caRootPem` and `intermediatePem` can contain **one or multiple PEM certificates concatenated**
- If `caRootPem` is **not** provided, default OS validation is used
- If the endpoint uses a private CA, you normally must provide `caRootPem`

### Certificate input formats (PEM or Base64)

The fields `caRootPem` and `intermediatePem` accept **multiple input formats**:

✅ **PEM text** (one or more concatenated certificates)  
✅ **PEM text with escaped newlines** (`\n`) for JSON compatibility  
✅ **Base64-encoded DER certificate**  
✅ **Base64-encoded PEM text** (the full PEM string encoded as base64)

This makes it easier to pass certificates using:
- JSON payloads (Lambda Test Tool / CLI)
- environment variables
- CI/CD pipelines

---

## Certificate revocation checking (CRL / OCSP)

This Lambda supports enabling or disabling certificate revocation checks during TLS validation.

### Parameters

- `revocationMode`: `NoCheck` (default), `Online`, `Offline`
- `revocationSoftFail`: `true` (default)

### What is "SoftFail"?

When `revocationMode` is `Online` or `Offline`, the TLS validation may fail if the runtime cannot reach CRL/OCSP endpoints or cannot verify revocation status.

If `revocationSoftFail = true`:

- TLS will continue when revocation status is **unknown/offline**
- TLS will still fail if the certificate is explicitly **revoked**
- This is recommended for AWS Lambda/VPC environments where CRL/OCSP endpoints may not be reachable.

If `revocationSoftFail = false`:

- TLS will fail when revocation cannot be verified (strict mode)

### Examples

Default behavior (revocation disabled):

```json
{
  "url": "https://example.com",
  "revocationMode": "NoCheck"
}
```

## Online revocation, strict mode:

```json
{
  "url": "https://example.com",
  "revocationMode": "Online",
  "revocationSoftFail": false
}
```
## Online revocation, soft mode (recommended):

```json
{
  "url": "https://example.com",
  "revocationMode": "Online",
  "revocationSoftFail": true
}
```
---

## Output format

The Lambda returns JSON including:

- `timingsMs` (phase durations)
- `waterfall` (start/end offsets since time zero)
- `tlsDetails` (when HTTPS is used)
- `asciiWaterfall`
- `warnings`

---

## CloudWatch logs output

CloudWatch logs will include:

1) URL / HTTP status / bytes  
2) TLS details (HTTPS only)  
3) TLS handshake coarse step breakdown  
4) Waterfall ASCII timeline  
5) Warning lines for slow phases (if any)  

---

## Notes about TLS "handshake step detail"

This Lambda reports coarse-grained TLS handshake steps:

- Create `SslStream`
- `AuthenticateAsClientAsync` (the actual handshake)
- Post-handshake inspection (protocol/cipher/cert extraction)

It does **not** provide packet-level TLS message timings (ClientHello/ServerHello/Certificate/etc.).
To get exact per-message TLS timings you typically need packet capture (pcap) and tools such as Wireshark/tshark.

---

## Local testing

You can test the Lambda logic locally without deploying to AWS.

### Option 1: AWS Lambda Test Tool (local emulator)

Install:

```bash
dotnet tool install --global Amazon.Lambda.TestTool-8.0
```

Run inside `src/Horacio-TLS-Lambda/`:

```bash
cd src/Horacio-TLS-Lambda
dotnet lambda-test-tool-8.0
```

Then open the local URL shown in the terminal and invoke using a JSON payload like:
```md
Tip: If you paste multi-line PEM blocks into the Lambda Test Tool JSON input, it will fail JSON parsing.
Use either:
- escaped PEM strings (`\n`)
- or Base64 input (recommended for long certs)
```

```json
{
  "url": "https://example.com",
  "method": "GET",
  "timeoutMs": 15000
}
```

### Option 2 (Recommended for developers): Run the local runner project

This repository includes a dedicated console runner:

- Project: `src/Horacio-TLS-Lambda.Local`

Build everything:

```bash
dotnet build .\src\Horacio-TLS-Lambda.Local\Horacio-TLS-Lambda.Local.csproj -c Release
```

Run the local runner (SystemTrust / public CAs):

```bash
dotnet run --project .\src\Horacio-TLS-Lambda.Local\Horacio-TLS-Lambda.Local.csproj -c Release -- "https://example.com"
```

Run the local runner using a private Root CA + Intermediate PEM files:

```bash
dotnet run --project src/Horacio-TLS-Lambda.Local -c Release -- \
  --url "https://your-private-endpoint.local/api/health" \
  --caRootPemFile "/path/to/root-ca.pem" \
  --intermediatePemFile "/path/to/intermediate.pem" \
  --revocationMode Online
```

Windows PowerShell example:

```powershell
dotnet run --project .\src\Horacio-TLS-Lambda.Local -c Release -- `
  --url "https://your-private-endpoint.local/api/health" `
  --caRootPemFile "D:\certs\root-ca.pem" `
  --intermediatePemFile "D:\certs\intermediate.pem" `
  --revocationMode Online
```

This runs the same Lambda handler logic and prints:
- TLS details
- ASCII waterfall
- warnings (if any phase > 1 second)
- JSON output

**Notes**
- If you omit `--caRootPemFile` and `--intermediatePemFile`, the runner uses **SystemTrust**.
- `--intermediatePemFile` alone typically does not help unless the Root CA is trusted (either by SystemTrust or via `--caRootPemFile`).


---

## Handler

The Lambda handler is configured as:

```text
HoracioTLSLambda::HoracioTLSLambda.Function::FunctionHandler
```

---

## Tools (helpers)

This repository includes helper scripts under `tools/`:

- `tools/nix/` (macOS/Linux)
- `tools/powershell/` (PowerShell)

Useful scripts:

- `pem_to_json.*` → converts a PEM file to a JSON-safe one-line string (`\n` escaped)
- `pem_to_base64.*` → base64-encodes the PEM text (easy to embed into JSON payloads)
- `pki_gen.*` → generates a lab Root CA + Intermediate CA + Server cert for testing

---

## Troubleshooting

### TLS fails with private CA
If your endpoint uses a private CA, you must provide `caRootPem`.  
Intermediates alone (`intermediatePem`) do not establish trust.

### Command not found: dotnet lambda
Make sure Amazon.Lambda.Tools is installed and your global tool path is present in your PATH.

---

## Contributing

Pull requests and improvements are welcome.
Please ensure changes are compatible with .NET 8 and AWS Lambda runtime constraints.

---

## Local runner JSON output

By default, the local runner does **NOT** print the full JSON output (to keep the terminal output readable).

To enable JSON output, add `--json`:

```bash
dotnet run --project ./src/Horacio-TLS-Lambda.Local/Horacio-TLS-Lambda.Local.csproj -c Release -- "https://example.com" --json
```

