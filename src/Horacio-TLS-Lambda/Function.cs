using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Amazon.Lambda.Core;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace HoracioTLSLambda;

// -------------------------
// Input / Output DTOs
// -------------------------

public class Request
{
    // URL to query (required)
    [JsonPropertyName("url")]
    public string Url { get; set; } = "";

    // HTTP method (default: GET)
    [JsonPropertyName("method")]
    public string Method { get; set; } = "GET";

    // Request timeout in milliseconds (default: 15000)
    [JsonPropertyName("timeoutMs")]
    public int TimeoutMs { get; set; } = 15000;

    // Custom Root CA bundle (PEM, optional). If provided, TLS validation is anchored to these roots.
    [JsonPropertyName("caRootPem")]
    public string? CaRootPem { get; set; }

    // Intermediate certificates (PEM, optional). Used to help chain building when servers omit intermediates.
    [JsonPropertyName("intermediatePem")]
    public string? IntermediatePem { get; set; }
}

public class Response
{
    [JsonPropertyName("url")]
    public string Url { get; set; } = "";

    [JsonPropertyName("statusCode")]
    public int StatusCode { get; set; }

    [JsonPropertyName("bytesRead")]
    public long BytesRead { get; set; }

    [JsonPropertyName("timingsMs")]
    public Timings TimingsMs { get; set; } = new();

    [JsonPropertyName("waterfall")]
    public Waterfall Waterfall { get; set; } = new();

    [JsonPropertyName("tlsDetails")]
    public TlsDetails? TlsDetails { get; set; }

    [JsonPropertyName("asciiWaterfall")]
    public string AsciiWaterfall { get; set; } = "";

    [JsonPropertyName("warnings")]
    public List<string> Warnings { get; set; } = new();

    // If the request fails before a status code is read, this will contain a short error.
    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

public class Timings
{
    [JsonPropertyName("dns")]
    public double Dns { get; set; }

    [JsonPropertyName("tcpConnect")]
    public double TcpConnect { get; set; }

    [JsonPropertyName("tlsHandshake")]
    public double TlsHandshake { get; set; }

    // Time to end-of-headers (raw includes DNS/TCP/TLS)
    [JsonPropertyName("ttfbRaw")]
    public double TtfbRaw { get; set; }

    // Approx net TTFB = raw - (dns + tcp + tls)
    [JsonPropertyName("ttfbNet")]
    public double TtfbNet { get; set; }

    [JsonPropertyName("transfer")]
    public double Transfer { get; set; }

    [JsonPropertyName("total")]
    public double Total { get; set; }

    // Coarse TLS internal steps
    [JsonPropertyName("tlsCreateSslStream")]
    public double TlsCreateSslStream { get; set; }

    [JsonPropertyName("tlsAuthenticateHandshake")]
    public double TlsAuthenticateHandshake { get; set; }

    [JsonPropertyName("tlsPostHandshakeInspection")]
    public double TlsPostHandshakeInspection { get; set; }
}

public class Waterfall
{
    [JsonPropertyName("dnsStart")] public double DnsStart { get; set; }
    [JsonPropertyName("dnsEnd")] public double DnsEnd { get; set; }

    [JsonPropertyName("tcpStart")] public double TcpStart { get; set; }
    [JsonPropertyName("tcpEnd")] public double TcpEnd { get; set; }

    [JsonPropertyName("tlsStart")] public double TlsStart { get; set; }
    [JsonPropertyName("tlsEnd")] public double TlsEnd { get; set; }

    [JsonPropertyName("ttfbStart")] public double TtfbStart { get; set; }
    [JsonPropertyName("ttfbEnd")] public double TtfbEnd { get; set; }

    [JsonPropertyName("transferStart")] public double TransferStart { get; set; }
    [JsonPropertyName("transferEnd")] public double TransferEnd { get; set; }

    [JsonPropertyName("totalStart")] public double TotalStart { get; set; }
    [JsonPropertyName("totalEnd")] public double TotalEnd { get; set; }
}

public class TlsDetails
{
    [JsonPropertyName("protocol")] public string? Protocol { get; set; }
    [JsonPropertyName("alpn")] public string? Alpn { get; set; }

    [JsonPropertyName("cipherAlgorithm")] public string? CipherAlgorithm { get; set; }
    [JsonPropertyName("cipherStrength")] public int CipherStrength { get; set; }

    [JsonPropertyName("hashAlgorithm")] public string? HashAlgorithm { get; set; }
    [JsonPropertyName("hashStrength")] public int HashStrength { get; set; }

    [JsonPropertyName("keyExchangeAlgorithm")] public string? KeyExchangeAlgorithm { get; set; }
    [JsonPropertyName("keyExchangeStrength")] public int KeyExchangeStrength { get; set; }

    [JsonPropertyName("remoteCertSubject")] public string? RemoteCertSubject { get; set; }
    [JsonPropertyName("remoteCertIssuer")] public string? RemoteCertIssuer { get; set; }
    [JsonPropertyName("remoteCertThumbprint")] public string? RemoteCertThumbprint { get; set; }
    [JsonPropertyName("remoteCertNotBefore")] public string? RemoteCertNotBefore { get; set; }
    [JsonPropertyName("remoteCertNotAfter")] public string? RemoteCertNotAfter { get; set; }

    [JsonPropertyName("remoteCertSans")] public List<string> RemoteCertSans { get; set; } = new();

    [JsonPropertyName("chainElements")] public int ChainElements { get; set; }
    [JsonPropertyName("chainStatus")] public List<string> ChainStatus { get; set; } = new();

    [JsonPropertyName("policyErrors")] public string? PolicyErrors { get; set; }
    [JsonPropertyName("validationMode")] public string ValidationMode { get; set; } = "SystemTrust";
}

// -------------------------
// Lambda entrypoint
// -------------------------

public class Function
{
    private const double WarningThresholdMs = 1000.0;

    public async Task<Response> FunctionHandler(Request input, ILambdaContext context)
    {
        if (string.IsNullOrWhiteSpace(input.Url))
            throw new ArgumentException("Missing 'url'.");

        var uri = new Uri(input.Url);
        if (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
            throw new ArgumentException("Only http/https schemes are supported.");

        // Default ports
        int port = uri.Port > 0 ? uri.Port : (uri.Scheme == Uri.UriSchemeHttps ? 443 : 80);

        using var cts = new CancellationTokenSource(input.TimeoutMs);
        var ct = cts.Token;

        var rootPool = BuildCertCollectionFromPem(input.CaRootPem, "caRootPem");
        var intermediatePool = BuildCertCollectionFromPem(input.IntermediatePem, "intermediatePem");

        var t = new TimingCollector();
        var sw0 = Stopwatch.StartNew();

        var response = new Response
        {
            Url = input.Url
        };

        try
        {
            // -------------------------
            // DNS
            // -------------------------
            t.DnsStart = sw0.Elapsed.TotalMilliseconds;
            var dnsSw = Stopwatch.StartNew();
            IPAddress[] ips = await Dns.GetHostAddressesAsync(uri.Host, ct).ConfigureAwait(false);
            dnsSw.Stop();

            t.DnsMs = dnsSw.Elapsed.TotalMilliseconds;
            t.DnsEnd = sw0.Elapsed.TotalMilliseconds;

            if (ips.Length == 0)
                throw new SocketException((int)SocketError.HostNotFound);

            var chosen = ChooseIp(ips);

            // -------------------------
            // TCP
            // -------------------------
            t.TcpStart = sw0.Elapsed.TotalMilliseconds;

            var sock = new Socket(chosen.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true
            };

            var tcpSw = Stopwatch.StartNew();
            await sock.ConnectAsync(new IPEndPoint(chosen, port), ct).ConfigureAwait(false);
            tcpSw.Stop();

            t.TcpMs = tcpSw.Elapsed.TotalMilliseconds;
            t.TcpEnd = sw0.Elapsed.TotalMilliseconds;

            await using var netStream = new NetworkStream(sock, ownsSocket: true);

            Stream ioStream = netStream;

            // -------------------------
            // TLS (HTTPS only)
            // -------------------------
            if (uri.Scheme == Uri.UriSchemeHttps)
            {
                t.TlsStart = sw0.Elapsed.TotalMilliseconds;

                t.TlsCreateStreamStart = sw0.Elapsed.TotalMilliseconds;

                RemoteCertificateValidationCallback certCb = (sender, certificate, chain, sslPolicyErrors) =>
                {
                    t.TlsPolicyErrors = sslPolicyErrors.ToString();

                    if (chain != null)
                    {
                        t.PlatformChainElements = chain.ChainElements?.Count ?? 0;
                        t.PlatformChainStatus = chain.ChainStatus
                            .Select(s => $"{s.Status}: {s.StatusInformation?.Trim()}")
                            .ToList();
                    }

                    // System trust store path
                    if (rootPool == null || rootPool.Count == 0)
                    {
                        t.TlsValidationMode = "SystemTrust";
                        return sslPolicyErrors == SslPolicyErrors.None;
                    }

                    // Custom root trust path
                    t.TlsValidationMode = "CustomRootTrust";

                    if (certificate is null)
                        return false;

                    using var customChain = new X509Chain();
                    customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    customChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                    customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    customChain.ChainPolicy.CustomTrustStore.Clear();
                    foreach (var root in rootPool)
                        customChain.ChainPolicy.CustomTrustStore.Add(root);

                    if (intermediatePool != null && intermediatePool.Count > 0)
                    {
                        foreach (var inter in intermediatePool)
                            customChain.ChainPolicy.ExtraStore.Add(inter);
                    }

                    var serverCert = new X509Certificate2(certificate);
                    bool ok = customChain.Build(serverCert);

                    t.CustomChainElements = customChain.ChainElements?.Count ?? 0;
                    t.CustomChainStatus = customChain.ChainStatus
                        .Select(s => $"{s.Status}: {s.StatusInformation?.Trim()}")
                        .ToList();

                    // Enforce hostname validation.
                    if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                        ok = false;

                    return ok;
                };

                var sslStream = new SslStream(netStream, leaveInnerStreamOpen: false, certCb);
                t.TlsCreateStreamEnd = sw0.Elapsed.TotalMilliseconds;

                t.TlsAuthStart = sw0.Elapsed.TotalMilliseconds;
                var tlsSw = Stopwatch.StartNew();

                // Manual HTTPS: force HTTP/1.1 semantics by not negotiating h2.
                // ALPN is optional; omitting it avoids h2 negotiation entirely.
                await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = uri.Host,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                }, ct).ConfigureAwait(false);

                tlsSw.Stop();
                t.TlsAuthEnd = sw0.Elapsed.TotalMilliseconds;

                t.TlsPostInfoStart = sw0.Elapsed.TotalMilliseconds;

                t.TlsMs = tlsSw.Elapsed.TotalMilliseconds;
                t.TlsEnd = sw0.Elapsed.TotalMilliseconds;

                t.NegotiatedProtocol = sslStream.SslProtocol.ToString();
                t.CipherAlgorithm = sslStream.CipherAlgorithm.ToString();
                t.CipherStrength = sslStream.CipherStrength;

                t.HashAlgorithm = sslStream.HashAlgorithm.ToString();
                t.HashStrength = sslStream.HashStrength;

                t.KeyExchangeAlgorithm = sslStream.KeyExchangeAlgorithm.ToString();
                t.KeyExchangeStrength = sslStream.KeyExchangeStrength;

                // ALPN may be empty when not negotiated.
                var alpnMem = sslStream.NegotiatedApplicationProtocol.Protocol;
                t.Alpn = alpnMem.IsEmpty ? "" : Encoding.ASCII.GetString(alpnMem.Span);

                if (sslStream.RemoteCertificate != null)
                {
                    var remote = new X509Certificate2(sslStream.RemoteCertificate);
                    t.RemoteCertSubject = remote.Subject;
                    t.RemoteCertIssuer = remote.Issuer;
                    t.RemoteCertThumbprint = remote.Thumbprint;
                    t.RemoteCertNotBefore = remote.NotBefore.ToUniversalTime().ToString("O");
                    t.RemoteCertNotAfter = remote.NotAfter.ToUniversalTime().ToString("O");
                    t.RemoteCertSans = ExtractSubjectAlternativeNames(remote);
                }

                t.TlsPostInfoEnd = sw0.Elapsed.TotalMilliseconds;

                ioStream = sslStream;
            }
            else
            {
                // HTTP path
                t.TlsValidationMode = "None(HTTP)";
                t.TlsStart = t.TlsEnd = sw0.Elapsed.TotalMilliseconds;
                t.TlsMs = 0;
            }

            // -------------------------
            // HTTP request / response (manual HTTP/1.1)
            // -------------------------
            string method = string.IsNullOrWhiteSpace(input.Method) ? "GET" : input.Method.Trim().ToUpperInvariant();
            string pathAndQuery = string.IsNullOrWhiteSpace(uri.PathAndQuery) ? "/" : uri.PathAndQuery;

            // For GET, do not send a body.
            // If you need POST bodies later, extend this safely.
            var requestText =
                $"{method} {pathAndQuery} HTTP/1.1\r\n" +
                $"Host: {uri.Host}\r\n" +
                "User-Agent: Horacio-TLS-Lambda/1.0\r\n" +
                "Accept: */*\r\n" +
                "Connection: close\r\n" +
                "\r\n";

            byte[] reqBytes = Encoding.ASCII.GetBytes(requestText);

            // TTFB: we measure until we have the full HTTP headers (end of header marker).
            t.TtfbStart = sw0.Elapsed.TotalMilliseconds;

            // Write request
            await ioStream.WriteAsync(reqBytes, 0, reqBytes.Length, ct).ConfigureAwait(false);
            await ioStream.FlushAsync(ct).ConfigureAwait(false);

            // Read response headers
            var headerReadSw = Stopwatch.StartNew();
            var (statusCode, headers, headerBytes) = await ReadHeadersAsync(ioStream, ct).ConfigureAwait(false);
            headerReadSw.Stop();

            t.TtfbEnd = sw0.Elapsed.TotalMilliseconds;
            t.TtfbRawMs = headerReadSw.Elapsed.TotalMilliseconds;

            // Net TTFB approximation
            t.TtfbNetMs = Math.Max(0, t.TtfbRawMs - (t.DnsMs + t.TcpMs + t.TlsMs));

            response.StatusCode = statusCode;

            // Transfer: read the body
            t.TransferStart = sw0.Elapsed.TotalMilliseconds;
            var transferSw = Stopwatch.StartNew();

            long bytesRead = 0;

            if (headers.TryGetValue("transfer-encoding", out var te) &&
                te.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                bytesRead = await ReadChunkedBodyAsync(ioStream, ct).ConfigureAwait(false);
            }
            else if (headers.TryGetValue("content-length", out var cl) &&
                     long.TryParse(cl.Trim(), out var contentLen) &&
                     contentLen >= 0)
            {
                bytesRead = await ReadFixedLengthBodyAsync(ioStream, contentLen, ct).ConfigureAwait(false);
            }
            else
            {
                // No content-length and not chunked: read to EOF.
                bytesRead = await ReadToEofAsync(ioStream, ct).ConfigureAwait(false);
            }

            transferSw.Stop();
            t.TransferMs = transferSw.Elapsed.TotalMilliseconds;
            t.TransferEnd = sw0.Elapsed.TotalMilliseconds;

            response.BytesRead = bytesRead;

            sw0.Stop();
            t.TotalMs = sw0.Elapsed.TotalMilliseconds;
            t.TotalEnd = t.TotalMs;

            var tlsStep = BuildTlsStepTimings(t);

            response.TimingsMs = new Timings
            {
                Dns = RoundMs(t.DnsMs),
                TcpConnect = RoundMs(t.TcpMs),
                TlsHandshake = RoundMs(t.TlsMs),
                TtfbRaw = RoundMs(t.TtfbRawMs),
                TtfbNet = RoundMs(t.TtfbNetMs),
                Transfer = RoundMs(t.TransferMs),
                Total = RoundMs(t.TotalMs),

                TlsCreateSslStream = RoundMs(tlsStep.CreateSslStreamMs),
                TlsAuthenticateHandshake = RoundMs(tlsStep.AuthenticateMs),
                TlsPostHandshakeInspection = RoundMs(tlsStep.PostHandshakeMs)
            };

            response.Waterfall = new Waterfall
            {
                DnsStart = RoundMs(t.DnsStart),
                DnsEnd = RoundMs(t.DnsEnd),
                TcpStart = RoundMs(t.TcpStart),
                TcpEnd = RoundMs(t.TcpEnd),
                TlsStart = RoundMs(t.TlsStart),
                TlsEnd = RoundMs(t.TlsEnd),
                TtfbStart = RoundMs(t.TtfbStart),
                TtfbEnd = RoundMs(t.TtfbEnd),
                TransferStart = RoundMs(t.TransferStart),
                TransferEnd = RoundMs(t.TransferEnd),
                TotalStart = 0,
                TotalEnd = RoundMs(t.TotalEnd)
            };

            response.TlsDetails = BuildTlsDetails(t);
            response.AsciiWaterfall = AsciiWaterfallAligned(response.Waterfall);
            response.Warnings = BuildWarnings(response.TimingsMs);

            // Logs
            context.Logger.LogLine($"URL: {input.Url}");
            context.Logger.LogLine($"HTTP {response.StatusCode} | Bytes: {response.BytesRead}");

            if (response.TlsDetails != null)
                LogTlsDetails(context, response.TlsDetails, response.TimingsMs);

            context.Logger.LogLine(response.AsciiWaterfall);
            foreach (var w in response.Warnings) context.Logger.LogLine(w);

            return response;
        }
        catch (Exception ex)
        {
            sw0.Stop();
            t.TotalMs = sw0.Elapsed.TotalMilliseconds;
            t.TotalEnd = t.TotalMs;

            // Return partial diagnostics with an error string.
            response.Error = $"{ex.GetType().Name}: {ex.Message}";

            response.TimingsMs = new Timings
            {
                Dns = RoundMs(t.DnsMs),
                TcpConnect = RoundMs(t.TcpMs),
                TlsHandshake = RoundMs(t.TlsMs),
                TtfbRaw = RoundMs(t.TtfbRawMs),
                TtfbNet = RoundMs(t.TtfbNetMs),
                Transfer = RoundMs(t.TransferMs),
                Total = RoundMs(t.TotalMs),
                TlsCreateSslStream = RoundMs(Math.Max(0, t.TlsCreateStreamEnd - t.TlsCreateStreamStart)),
                TlsAuthenticateHandshake = RoundMs(Math.Max(0, t.TlsAuthEnd - t.TlsAuthStart)),
                TlsPostHandshakeInspection = RoundMs(Math.Max(0, t.TlsPostInfoEnd - t.TlsPostInfoStart))
            };

            response.Waterfall = new Waterfall
            {
                DnsStart = RoundMs(t.DnsStart),
                DnsEnd = RoundMs(t.DnsEnd),
                TcpStart = RoundMs(t.TcpStart),
                TcpEnd = RoundMs(t.TcpEnd),
                TlsStart = RoundMs(t.TlsStart),
                TlsEnd = RoundMs(t.TlsEnd),
                TtfbStart = RoundMs(t.TtfbStart),
                TtfbEnd = RoundMs(t.TtfbEnd),
                TransferStart = RoundMs(t.TransferStart),
                TransferEnd = RoundMs(t.TransferEnd),
                TotalStart = 0,
                TotalEnd = RoundMs(t.TotalEnd)
            };

            response.TlsDetails = BuildTlsDetails(t);
            response.AsciiWaterfall = AsciiWaterfallAligned(response.Waterfall);
            response.Warnings = BuildWarnings(response.TimingsMs);

            context.Logger.LogLine($"ERROR: {response.Error}");
            if (response.TlsDetails != null)
                LogTlsDetails(context, response.TlsDetails, response.TimingsMs);

            context.Logger.LogLine(response.AsciiWaterfall);
            foreach (var w in response.Warnings) context.Logger.LogLine(w);

            return response;
        }
    }

    // -------------------------
    // HTTP parsing helpers
    // -------------------------

    private static async Task<(int StatusCode, Dictionary<string, string> Headers, byte[] HeaderBytes)> ReadHeadersAsync(Stream s, CancellationToken ct)
    {
        // Read until \r\n\r\n
        using var ms = new MemoryStream();
        byte[] buf = ArrayPool<byte>.Shared.Rent(4096);

        try
        {
            int found = -1;
            while (true)
            {
                int n = await s.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                if (n <= 0)
                    throw new IOException("Connection closed before headers were received.");

                ms.Write(buf, 0, n);

                var data = ms.GetBuffer();
                int len = (int)ms.Length;

                found = IndexOfHeaderTerminator(data, len);
                if (found >= 0)
                {
                    // We have full headers in [0..found+4)
                    break;
                }

                // Prevent runaway memory usage for pathological endpoints
                if (ms.Length > 1024 * 1024)
                    throw new IOException("Headers too large (> 1MB).");
            }

            byte[] all = ms.ToArray();
            int headerEnd = IndexOfHeaderTerminator(all, all.Length);
            if (headerEnd < 0)
                throw new IOException("Header terminator not found.");

            int headerLen = headerEnd + 4;
            byte[] headerBytes = new byte[headerLen];
            Buffer.BlockCopy(all, 0, headerBytes, 0, headerLen);

            string headerText = Encoding.ASCII.GetString(headerBytes);
            var lines = headerText.Split(new[] { "\r\n" }, StringSplitOptions.None);

            if (lines.Length == 0)
                throw new IOException("Empty response headers.");

            // Status line: HTTP/1.1 200 OK
            int statusCode = ParseStatusCode(lines[0]);

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (string.IsNullOrEmpty(line)) break;

                int colon = line.IndexOf(':');
                if (colon <= 0) continue;

                string name = line.Substring(0, colon).Trim();
                string value = line.Substring(colon + 1).Trim();
                headers[name] = value;
            }

            // Note: we intentionally do not attempt to keep the extra buffered body bytes here.
            // For a timing tool, reading the body from the stream after headers is sufficient when Connection: close is used.
            // If you later need perfect accounting, we can implement a "prefetch buffer" wrapper.

            return (statusCode, headers, headerBytes);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    private static int IndexOfHeaderTerminator(byte[] data, int len)
    {
        // Find \r\n\r\n
        for (int i = 3; i < len; i++)
        {
            if (data[i - 3] == (byte)'\r' &&
                data[i - 2] == (byte)'\n' &&
                data[i - 1] == (byte)'\r' &&
                data[i] == (byte)'\n')
                return i - 3;
        }
        return -1;
    }

    private static int ParseStatusCode(string statusLine)
    {
        // Expected: HTTP/1.1 200 OK
        // Split and parse the second token.
        var parts = statusLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !int.TryParse(parts[1], out var code))
            return 0;
        return code;
    }

    private static async Task<long> ReadFixedLengthBodyAsync(Stream s, long length, CancellationToken ct)
    {
        byte[] buf = ArrayPool<byte>.Shared.Rent(64 * 1024);
        long total = 0;

        try
        {
            while (total < length)
            {
                int want = (int)Math.Min(buf.Length, length - total);
                int n = await s.ReadAsync(buf, 0, want, ct).ConfigureAwait(false);
                if (n <= 0) break;
                total += n;
            }
            return total;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    private static async Task<long> ReadToEofAsync(Stream s, CancellationToken ct)
    {
        byte[] buf = ArrayPool<byte>.Shared.Rent(64 * 1024);
        long total = 0;

        try
        {
            while (true)
            {
                int n = await s.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                if (n <= 0) break;
                total += n;
            }
            return total;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    private static async Task<long> ReadChunkedBodyAsync(Stream s, CancellationToken ct)
    {
        // Minimal chunked decoder: reads chunk size lines (hex), then that many bytes, until 0.
        long total = 0;

        while (true)
        {
            string line = await ReadLineAsciiAsync(s, ct).ConfigureAwait(false);
            if (line.Length == 0)
                continue;

            // Chunk size may have extensions: "1A;ext=value"
            int semi = line.IndexOf(';');
            if (semi >= 0) line = line.Substring(0, semi);

            if (!int.TryParse(line.Trim(), System.Globalization.NumberStyles.HexNumber, null, out int chunkSize))
                throw new IOException("Invalid chunk size.");

            if (chunkSize == 0)
            {
                // Consume trailing headers (optional) until empty line
                while (true)
                {
                    string trailer = await ReadLineAsciiAsync(s, ct).ConfigureAwait(false);
                    if (trailer.Length == 0) break;
                }
                break;
            }

            total += await ReadFixedLengthBodyAsync(s, chunkSize, ct).ConfigureAwait(false);

            // Consume the trailing CRLF after chunk
            await ReadExactAsync(s, 2, ct).ConfigureAwait(false);
        }

        return total;
    }

    private static async Task<string> ReadLineAsciiAsync(Stream s, CancellationToken ct)
    {
        // Read until CRLF
        using var ms = new MemoryStream();
        while (true)
        {
            int b = await ReadByteAsync(s, ct).ConfigureAwait(false);
            if (b < 0) throw new IOException("Unexpected EOF while reading line.");

            if (b == '\r')
            {
                int n = await ReadByteAsync(s, ct).ConfigureAwait(false);
                if (n < 0) throw new IOException("Unexpected EOF while reading line.");
                if (n == '\n') break;

                ms.WriteByte((byte)'\r');
                ms.WriteByte((byte)n);
                continue;
            }

            ms.WriteByte((byte)b);

            if (ms.Length > 64 * 1024)
                throw new IOException("Line too long.");
        }

        return Encoding.ASCII.GetString(ms.ToArray()).TrimEnd();
    }

    private static async Task<int> ReadByteAsync(Stream s, CancellationToken ct)
    {
        byte[] one = new byte[1];
        int n = await s.ReadAsync(one, 0, 1, ct).ConfigureAwait(false);
        return n == 1 ? one[0] : -1;
    }

    private static async Task ReadExactAsync(Stream s, int bytes, CancellationToken ct)
    {
        byte[] buf = ArrayPool<byte>.Shared.Rent(bytes);
        int read = 0;

        try
        {
            while (read < bytes)
            {
                int n = await s.ReadAsync(buf, read, bytes - read, ct).ConfigureAwait(false);
                if (n <= 0) throw new IOException("Unexpected EOF.");
                read += n;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    // -------------------------
    // Warnings
    // -------------------------

    private static List<string> BuildWarnings(Timings t)
    {
        var warnings = new List<string>();

        void Check(string name, double ms)
        {
            if (ms > WarningThresholdMs)
                warnings.Add($"WARNING: {name} took {ms:0.00} ms (> {WarningThresholdMs:0} ms).");
        }

        Check("DNS", t.Dns);
        Check("TCP connect", t.TcpConnect);
        Check("TLS handshake", t.TlsHandshake);
        Check("TTFB (raw)", t.TtfbRaw);
        Check("TTFB (net)", t.TtfbNet);
        Check("Transfer", t.Transfer);
        Check("Total", t.Total);

        Check("TLS Authenticate (handshake)", t.TlsAuthenticateHandshake);

        return warnings;
    }

    // -------------------------
    // TLS details & logging
    // -------------------------

    private static TlsDetails? BuildTlsDetails(TimingCollector t)
    {
        if (string.Equals(t.TlsValidationMode, "None(HTTP)", StringComparison.OrdinalIgnoreCase))
            return null;

        if (t.NegotiatedProtocol == null && t.RemoteCertSubject == null && t.TlsMs <= 0)
            return null;

        var chainStatus = new List<string>();

        if (string.Equals(t.TlsValidationMode, "CustomRootTrust", StringComparison.OrdinalIgnoreCase))
            chainStatus.AddRange(t.CustomChainStatus ?? new List<string>());
        else
            chainStatus.AddRange(t.PlatformChainStatus ?? new List<string>());

        int chainElements = string.Equals(t.TlsValidationMode, "CustomRootTrust", StringComparison.OrdinalIgnoreCase)
            ? t.CustomChainElements
            : t.PlatformChainElements;

        return new TlsDetails
        {
            Protocol = t.NegotiatedProtocol,
            Alpn = string.IsNullOrWhiteSpace(t.Alpn) ? null : t.Alpn,
            CipherAlgorithm = t.CipherAlgorithm,
            CipherStrength = t.CipherStrength,
            HashAlgorithm = t.HashAlgorithm,
            HashStrength = t.HashStrength,
            KeyExchangeAlgorithm = t.KeyExchangeAlgorithm,
            KeyExchangeStrength = t.KeyExchangeStrength,
            RemoteCertSubject = t.RemoteCertSubject,
            RemoteCertIssuer = t.RemoteCertIssuer,
            RemoteCertThumbprint = t.RemoteCertThumbprint,
            RemoteCertNotBefore = t.RemoteCertNotBefore,
            RemoteCertNotAfter = t.RemoteCertNotAfter,
            RemoteCertSans = t.RemoteCertSans ?? new List<string>(),
            ChainElements = chainElements,
            ChainStatus = chainStatus,
            PolicyErrors = t.TlsPolicyErrors,
            ValidationMode = t.TlsValidationMode ?? "SystemTrust"
        };
    }

    private static void LogTlsDetails(ILambdaContext context, TlsDetails tls, Timings timings)
    {
        context.Logger.LogLine("TLS details:");
        context.Logger.LogLine($"  Validation: {tls.ValidationMode}");
        context.Logger.LogLine($"  Protocol  : {tls.Protocol}");
        context.Logger.LogLine($"  ALPN      : {tls.Alpn}");
        context.Logger.LogLine($"  Cipher    : {tls.CipherAlgorithm} ({tls.CipherStrength})");
        context.Logger.LogLine($"  Hash      : {tls.HashAlgorithm} ({tls.HashStrength})");
        context.Logger.LogLine($"  KeyEx     : {tls.KeyExchangeAlgorithm} ({tls.KeyExchangeStrength})");
        context.Logger.LogLine($"  PolicyErr : {tls.PolicyErrors}");

        if (!string.IsNullOrWhiteSpace(tls.RemoteCertSubject))
        {
            context.Logger.LogLine($"  Cert Subject: {tls.RemoteCertSubject}");
            context.Logger.LogLine($"  Cert Issuer : {tls.RemoteCertIssuer}");
            context.Logger.LogLine($"  Cert Thumb  : {tls.RemoteCertThumbprint}");
            context.Logger.LogLine($"  Cert Valid  : {tls.RemoteCertNotBefore} -> {tls.RemoteCertNotAfter}");
        }

        if (tls.RemoteCertSans.Count > 0)
            context.Logger.LogLine($"  SANs       : {string.Join(", ", tls.RemoteCertSans)}");

        if (tls.ChainElements > 0)
            context.Logger.LogLine($"  Chain      : Elements={tls.ChainElements}; Status={(tls.ChainStatus.Count == 0 ? "NoError" : "See below")}");

        foreach (var s in tls.ChainStatus.Take(10))
            context.Logger.LogLine($"    ChainStatus: {s}");

        context.Logger.LogLine("TLS handshake steps (coarse-grained):");
        context.Logger.LogLine($"  Create SslStream  : {timings.TlsCreateSslStream:0.00} ms");
        context.Logger.LogLine($"  Authenticate (HS) : {timings.TlsAuthenticateHandshake:0.00} ms");
        context.Logger.LogLine($"  Post HS info      : {timings.TlsPostHandshakeInspection:0.00} ms");
    }

    private static (double CreateSslStreamMs, double AuthenticateMs, double PostHandshakeMs) BuildTlsStepTimings(TimingCollector t)
    {
        double create = Math.Max(0, t.TlsCreateStreamEnd - t.TlsCreateStreamStart);
        double auth = Math.Max(0, t.TlsAuthEnd - t.TlsAuthStart);
        double post = Math.Max(0, t.TlsPostInfoEnd - t.TlsPostInfoStart);
        return (create, auth, post);
    }

    // -------------------------
    // Waterfall rendering (aligned)
    // -------------------------

    private static string AsciiWaterfallAligned(Waterfall w)
    {
        const int labelWidth = 6;
        const int cols = 78;
        const int msWidth = 10;

        var total = Math.Max(1.0, w.TotalEnd);
        double msPerCol = total / cols;

        string Line(string name, double start, double end)
	{
	    // Use floor/ceil mapping to avoid rounding pushing start to cols
	    int startCol = (int)Math.Floor(start / msPerCol);
	    int endCol = (int)Math.Ceiling(end / msPerCol);

	    // Ensure at least a 1-column bar
	    if (endCol <= startCol) endCol = startCol + 1;

	    // Clamp to keep bars inside [0..cols]
	    // startCol must be <= cols-1 so we can always draw at least 1 char.
	    startCol = Math.Clamp(startCol, 0, cols - 1);
	    endCol = Math.Clamp(endCol, startCol + 1, cols);

	    int barLen = endCol - startCol;                 // >= 1
	    int tailSpaces = cols - (startCol + barLen);    // >= 0

	    var sb = new StringBuilder();
	    sb.Append(name.PadRight(labelWidth));
	    sb.Append(" |");

	    if (startCol > 0) sb.Append(' ', startCol);
	    sb.Append(new string('#', barLen));
	    if (tailSpaces > 0) sb.Append(' ', tailSpaces);

	    sb.Append("| ");
	    double dur = Math.Max(0, end - start);
	    sb.Append(dur.ToString("0.00").PadLeft(msWidth));
	    sb.Append(" ms");

	    return sb.ToString();
	}

        var outSb = new StringBuilder();
        outSb.AppendLine($"Waterfall (0 -> {w.TotalEnd:0.00} ms)");
        outSb.AppendLine(Line("DNS", w.DnsStart, w.DnsEnd));
        outSb.AppendLine(Line("TCP", w.TcpStart, w.TcpEnd));
        outSb.AppendLine(Line("TLS", w.TlsStart, w.TlsEnd));
        outSb.AppendLine(Line("TTFB", w.TtfbStart, w.TtfbEnd));
        outSb.AppendLine(Line("XFER", w.TransferStart, w.TransferEnd));
        outSb.AppendLine(Line("TOTAL", w.TotalStart, w.TotalEnd));
        return outSb.ToString();
    }

    // -------------------------
    // Helpers
    // -------------------------

    private static IPAddress ChooseIp(IPAddress[] ips)
    {
        foreach (var ip in ips)
            if (ip.AddressFamily == AddressFamily.InterNetwork)
                return ip;
        return ips[0];
    }

    private static double RoundMs(double v) => Math.Round(v, 2);

    private static X509Certificate2Collection? BuildCertCollectionFromPem(string? pem, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(pem))
            return null;

        var certs = new X509Certificate2Collection();
        foreach (var onePem in SplitPemCertificates(pem))
        {
            try
            {
                var cert = X509Certificate2.CreateFromPem(onePem);
                certs.Add(new X509Certificate2(cert.Export(X509ContentType.Cert)));
            }
            catch
            {
                throw new ArgumentException($"Invalid {fieldName}: unable to parse one or more PEM certificates.");
            }
        }

        if (certs.Count == 0)
            throw new ArgumentException($"Invalid {fieldName}: no PEM certificates found.");

        return certs;
    }

    private static IEnumerable<string> SplitPemCertificates(string pem)
    {
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";

        int idx = 0;
        while (true)
        {
            int b = pem.IndexOf(begin, idx, StringComparison.Ordinal);
            if (b < 0) yield break;

            int e = pem.IndexOf(end, b, StringComparison.Ordinal);
            if (e < 0) throw new ArgumentException("Invalid PEM: missing END CERTIFICATE.");

            e += end.Length;
            string block = pem.Substring(b, e - b);
            idx = e;

            yield return block.Replace("\r\n", "\n").Trim() + "\n";
        }
    }

    private static List<string> ExtractSubjectAlternativeNames(X509Certificate2 cert)
    {
        var list = new List<string>();

        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value != "2.5.29.17")
                continue;

            try
            {
                var asn = new AsnEncodedData(ext.Oid, ext.RawData);
                var formatted = asn.Format(true);

                var lines = formatted
                    .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim())
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .ToList();

                list.AddRange(lines);
            }
            catch
            {
                // Best effort only.
            }
        }

        return list;
    }

    private sealed class TimingCollector
    {
        public double DnsMs, TcpMs, TlsMs, TransferMs, TotalMs;
        public double TtfbRawMs, TtfbNetMs;

        public double DnsStart, DnsEnd;
        public double TcpStart, TcpEnd;
        public double TlsStart, TlsEnd;
        public double TtfbStart, TtfbEnd;
        public double TransferStart, TransferEnd;
        public double TotalStart = Stopwatch.GetTimestamp(), TotalEnd = Stopwatch.GetTimestamp();

        public double TlsCreateStreamStart, TlsCreateStreamEnd;
        public double TlsAuthStart, TlsAuthEnd;
        public double TlsPostInfoStart, TlsPostInfoEnd;

        public string? NegotiatedProtocol;
        public string? CipherAlgorithm;
        public int CipherStrength;
        public string? HashAlgorithm;
        public int HashStrength;
        public string? KeyExchangeAlgorithm;
        public int KeyExchangeStrength;
        public string? Alpn;

        public string? RemoteCertSubject;
        public string? RemoteCertIssuer;
        public string? RemoteCertThumbprint;
        public string? RemoteCertNotBefore;
        public string? RemoteCertNotAfter;
        public List<string>? RemoteCertSans;

        public string? TlsPolicyErrors;
        public string? TlsValidationMode;

        public int PlatformChainElements;
        public List<string>? PlatformChainStatus;

        public int CustomChainElements;
        public List<string>? CustomChainStatus;
    }
}
