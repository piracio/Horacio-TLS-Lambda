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

Example waterfall output:

```
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

```
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
    └── Horacio-TLS-Lambda/
        ├── Horacio-TLS-Lambda.csproj
        ├── Function.cs
        ├── aws-lambda-tools-defaults.json
        └── Horacio-TLS-Lambda.sln
```

---

## Build

From the project directory:

```bash
cd src/Horacio-TLS-Lambda
dotnet build -c Release
```

---

## Deploy

From the project directory:

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

---

## Input parameters

The Lambda input event supports:

| Field | Type | Required | Default | Description |
|------|------|----------|---------|-------------|
| `url` | string | Yes | (none) | HTTP/HTTPS URL to query |
| `method` | string | No | `GET` | HTTP method |
| `timeoutMs` | int | No | `15000` | Timeout for the full request |
| `caRootPem` | string | No | empty | Root CA bundle in PEM format (enables CustomRootTrust) |
| `intermediatePem` | string | No | empty | Intermediate certificates in PEM format |

Important notes:
- `caRootPem` and `intermediatePem` can contain **one or multiple PEM certificates concatenated**
- If `caRootPem` is **not** provided, default OS validation is used
- If the endpoint uses a private CA, you normally must provide `caRootPem`

---

## Output format

The Lambda returns JSON including:

- `timingsMs` (phase durations)
- `waterfall` (start/end offsets since time zero)
- `tlsDetails` (when HTTPS is used)
- `asciiWaterfall`
- `warnings`

Example output structure:

```json
{
  "url": "https://example.com",
  "statusCode": 200,
  "bytesRead": 1256,
  "timingsMs": {
    "dns": 12.3,
    "tcpConnect": 18.4,
    "tlsHandshake": 52.1,
    "ttfbNet": 90.0,
    "ttfbRaw": 172.0,
    "transfer": 42.3,
    "total": 245.12,
    "tlsCreateSslStream": 0.05,
    "tlsAuthenticateHandshake": 45.12,
    "tlsPostHandshakeInspection": 0.6
  },
  "waterfall": {
    "dnsStart": 0,
    "dnsEnd": 12.3,
    "tcpStart": 12.3,
    "tcpEnd": 30.7,
    "tlsStart": 30.7,
    "tlsEnd": 82.8,
    "ttfbStart": 82.8,
    "ttfbEnd": 172,
    "transferStart": 172,
    "transferEnd": 214.3,
    "totalStart": 0,
    "totalEnd": 245.12
  },
  "tlsDetails": {
    "validationMode": "SystemTrust",
    "protocol": "Tls13",
    "alpn": "h2",
    "cipherAlgorithm": "Aes256",
    "cipherStrength": 256,
    "remoteCertSubject": "CN=example.com",
    "remoteCertIssuer": "CN=Example Intermediate CA",
    "remoteCertNotBefore": "2026-01-01T00:00:00.0000000Z",
    "remoteCertNotAfter": "2027-01-01T00:00:00.0000000Z",
    "remoteCertSans": ["DNS Name=example.com", "DNS Name=www.example.com"],
    "chainElements": 3,
    "chainStatus": [],
    "policyErrors": "None"
  },
  "asciiWaterfall": "Waterfall (0 → 245.12 ms)\n...",
  "warnings": []
}
```

---

## CloudWatch logs output

CloudWatch logs will include:

1) URL / HTTP status / bytes  
2) TLS details (HTTPS only)  
3) TLS handshake coarse step breakdown  
4) Waterfall ASCII timeline  
5) Warning lines for slow phases (if any)  

---

## Notes about TLS “handshake step detail”

This Lambda reports coarse-grained TLS handshake steps:

- Create `SslStream`
- `AuthenticateAsClientAsync` (the actual handshake)
- Post-handshake inspection (protocol/cipher/cert extraction)

It does **not** provide packet-level TLS message timings (ClientHello/ServerHello/Certificate/etc.).
To get exact per-message TLS timings you typically need packet capture (pcap) and tools such as Wireshark/tshark.

---

## Handler

The Lambda handler is configured as:

```
HoracioTLSLambda::HoracioTLSLambda.Function::FunctionHandler
```

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
