using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography; // Needed for AsnEncodedData
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

    // Waterfall offsets (start/end) in ms from time zero.
    [JsonPropertyName("waterfall")]
    public Waterfall Waterfall { get; set; } = new();

    [JsonPropertyName("tlsDetails")]
    public TlsDetails? TlsDetails { get; set; }

    // ASCII waterfall intended for CloudWatch logs.
    [JsonPropertyName("asciiWaterfall")]
    public string AsciiWaterfall { get; set; } = "";

    // List of warnings (phase durations > 1000 ms)
    [JsonPropertyName("warnings")]
    public List<string> Warnings { get; set; } = new();
}

public class Timings
{
    // Phase durations in milliseconds
    [JsonPropertyName("dns")]
    public double Dns { get; set; }

    [JsonPropertyName("tcpConnect")]
    public double TcpConnect { get; set; }

    [JsonPropertyName("tlsHandshake")]
    public double TlsHandshake { get; set; }

    // Net TTFB: "time to headers" minus DNS/TCP/TLS
    [JsonPropertyName("ttfbNet")]
    public double TtfbNet { get; set; }

    // Raw time to headers (includes DNS/TCP/TLS)
    [JsonPropertyName("ttfbRaw")]
    public double TtfbRaw { get; set; }

    [JsonPropertyName("transfer")]
    public double Transfer { get; set; }

    [JsonPropertyName("total")]
    public double Total { get; set; }

    // Coarse-grained TLS internal steps (not packet-level TLS message timings)
    [JsonPropertyName("tlsCreateSslStream")]
    public double TlsCreateSslStream { get; set; }

    [JsonPropertyName("tlsAuthenticateHandshake")]
    public double TlsAuthenticateHandshake { get; set; }

    [JsonPropertyName("tlsPostHandshakeInspection")]
    public double TlsPostHandshakeInspection { get; set; }
}

public class Waterfall
{
    // Offsets are expressed in milliseconds since start (0 ms).

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
    [JsonPropertyName("protocol")]
    public string? Protocol { get; set; }

    [JsonPropertyName("alpn")]
    public string? Alpn { get; set; }

    [JsonPropertyName("cipherAlgorithm")]
    public string? CipherAlgorithm { get; set; }

    [JsonPropertyName("cipherStrength")]
    public int CipherStrength { get; set; }

    [JsonPropertyName("hashAlgorithm")]
    public string? HashAlgorithm { get; set; }

    [JsonPropertyName("hashStrength")]
    public int HashStrength { get; set; }

    [JsonPropertyName("keyExchangeAlgorithm")]
    public string? KeyExchangeAlgorithm { get; set; }

    [JsonPropertyName("keyExchangeStrength")]
    public int KeyExchangeStrength { get; set; }

    [JsonPropertyName("remoteCertSubject")]
    public string? RemoteCertSubject { get; set; }

    [JsonPropertyName("remoteCertIssuer")]
    public string? RemoteCertIssuer { get; set; }

    [JsonPropertyName("remoteCertThumbprint")]
    public string? RemoteCertThumbprint { get; set; }

    [JsonPropertyName("remoteCertNotBefore")]
    public string? RemoteCertNotBefore { get; set; }

    [JsonPropertyName("remoteCertNotAfter")]
    public string? RemoteCertNotAfter { get; set; }

    [JsonPropertyName("remoteCertSans")]
    public List<string> RemoteCertSans { get; set; } = new();

    [JsonPropertyName("chainElements")]
    public int ChainElements { get; set; }

    [JsonPropertyName("chainStatus")]
    public List<string> ChainStatus { get; set; } = new();

    [JsonPropertyName("policyErrors")]
    public string? PolicyErrors { get; set; }

    [JsonPropertyName("validationMode")]
    public string ValidationMode { get; set; } = "SystemTrust";
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

        using var cts = new CancellationTokenSource(input.TimeoutMs);

        // Parse optional PEM inputs.
        // Root CAs are used as trust anchors; intermediates are used for chain completion.
        var rootPool = BuildCertCollectionFromPem(input.CaRootPem, "caRootPem");
        var intermediatePool = BuildCertCollectionFromPem(input.IntermediatePem, "intermediatePem");

        var t = new TimingCollector();
        var baseSw = Stopwatch.StartNew();

        // We instrument DNS/TCP/TLS by taking control of the connection establishment.
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),

            ConnectCallback = async (ctx, ct) =>
            {
                var host = ctx.DnsEndPoint.Host;
                var port = ctx.DnsEndPoint.Port;

                // DNS resolution
                t.DnsStart = baseSw.Elapsed.TotalMilliseconds;
                var dnsSw = Stopwatch.StartNew();
                IPAddress[] ips = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
                dnsSw.Stop();
                t.DnsMs = dnsSw.Elapsed.TotalMilliseconds;
                t.DnsEnd = baseSw.Elapsed.TotalMilliseconds;

                if (ips.Length == 0)
                    throw new SocketException((int)SocketError.HostNotFound);

                var chosen = ChooseIp(ips);

                // TCP connect
                t.TcpStart = baseSw.Elapsed.TotalMilliseconds;

                var sock = new Socket(chosen.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true
                };

                var tcpSw = Stopwatch.StartNew();
                await sock.ConnectAsync(new IPEndPoint(chosen, port), ct).ConfigureAwait(false);
                tcpSw.Stop();
                t.TcpMs = tcpSw.Elapsed.TotalMilliseconds;
                t.TcpEnd = baseSw.Elapsed.TotalMilliseconds;

                var netStream = new NetworkStream(sock, ownsSocket: true);

                // If the scheme is HTTP (no TLS), return the raw network stream.
                if (uri.Scheme == Uri.UriSchemeHttp)
                {
                    t.TlsMs = 0;
                    t.TlsStart = t.TlsEnd = baseSw.Elapsed.TotalMilliseconds;
                    t.TlsValidationMode = "None(HTTP)";
                    return netStream;
                }

                // TLS handshake (coarse timing)
                t.TlsStart = baseSw.Elapsed.TotalMilliseconds;

                // Step 1: Create SslStream
                t.TlsCreateStreamStart = baseSw.Elapsed.TotalMilliseconds;

                RemoteCertificateValidationCallback certCb = (sender, certificate, chain, sslPolicyErrors) =>
                {
                    t.TlsPolicyErrors = sslPolicyErrors.ToString();

                    // Capture chain status as seen by the platform (when available).
                    // Note: 'chain' can be null in some edge cases.
                    if (chain != null)
                    {
                        t.PlatformChainElements = chain.ChainElements?.Count ?? 0;
                        t.PlatformChainStatus = chain.ChainStatus
                            .Select(s => $"{s.Status}: {s.StatusInformation?.Trim()}")
                            .ToList();
                    }

                    // If no custom root CA is provided, use the system trust store validation.
                    if (rootPool == null || rootPool.Count == 0)
                    {
                        t.TlsValidationMode = "SystemTrust";
                        return sslPolicyErrors == SslPolicyErrors.None;
                    }

                    t.TlsValidationMode = "CustomRootTrust";

                    if (certificate is null)
                        return false;

                    using var customChain = new X509Chain();

                    // In Lambda environments, CRL/OCSP checks can add latency or fail due to networking constraints.
                    customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    customChain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                    // Anchor chain building to a custom root store.
                    customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    customChain.ChainPolicy.CustomTrustStore.Clear();

                    foreach (var root in rootPool)
                        customChain.ChainPolicy.CustomTrustStore.Add(root);

                    // Add intermediates to ExtraStore to help build the chain if the server does not provide them.
                    if (intermediatePool != null && intermediatePool.Count > 0)
                    {
                        foreach (var inter in intermediatePool)
                            customChain.ChainPolicy.ExtraStore.Add(inter);
                    }

                    var serverCert = new X509Certificate2(certificate);
                    bool ok = customChain.Build(serverCert);

                    // Capture custom chain diagnostics.
                    t.CustomChainElements = customChain.ChainElements?.Count ?? 0;
                    t.CustomChainStatus = customChain.ChainStatus
                        .Select(s => $"{s.Status}: {s.StatusInformation?.Trim()}")
                        .ToList();

                    // Enforce hostname validation: if the platform reported a name mismatch, fail.
                    if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
                        ok = false;

                    return ok;
                };

                var sslStream = new SslStream(netStream, leaveInnerStreamOpen: false, certCb);
                t.TlsCreateStreamEnd = baseSw.Elapsed.TotalMilliseconds;

                // Step 2: Authenticate (this is the handshake)
                t.TlsAuthStart = baseSw.Elapsed.TotalMilliseconds;

                var tlsSw = Stopwatch.StartNew();
                await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,

                    // ALPN hint: attempt HTTP/2, then HTTP/1.1.
                    ApplicationProtocols = new List<SslApplicationProtocol>
                    {
                        SslApplicationProtocol.Http2,
                        SslApplicationProtocol.Http11
                    }
                }, ct).ConfigureAwait(false);
                tlsSw.Stop();

                t.TlsAuthEnd = baseSw.Elapsed.TotalMilliseconds;

                // Step 3: Post-handshake inspection
                t.TlsPostInfoStart = baseSw.Elapsed.TotalMilliseconds;

                t.TlsMs = tlsSw.Elapsed.TotalMilliseconds;
                t.TlsEnd = baseSw.Elapsed.TotalMilliseconds;

                // Capture negotiated TLS properties.
                t.NegotiatedProtocol = sslStream.SslProtocol.ToString();
                t.CipherAlgorithm = sslStream.CipherAlgorithm.ToString();
                t.CipherStrength = sslStream.CipherStrength;

                t.HashAlgorithm = sslStream.HashAlgorithm.ToString();
                t.HashStrength = sslStream.HashStrength;

                t.KeyExchangeAlgorithm = sslStream.KeyExchangeAlgorithm.ToString();
                t.KeyExchangeStrength = sslStream.KeyExchangeStrength;

                // FIX: ALPN is ReadOnlyMemory<byte>, not a nullable reference type.
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

                t.TlsPostInfoEnd = baseSw.Elapsed.TotalMilliseconds;

                return sslStream;
            }
        };

        using var client = new HttpClient(handler)
        {
            // We use CancellationTokenSource for timeouts to keep timing consistent.
            Timeout = Timeout.InfiniteTimeSpan
        };

        using var req = new HttpRequestMessage(new HttpMethod(input.Method ?? "GET"), uri);

        // TTFB is measured as "time to response headers".
        t.TotalStart = 0;
        t.TtfbStart = baseSw.Elapsed.TotalMilliseconds;

        var ttfbSw = Stopwatch.StartNew();
        using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token)
                                     .ConfigureAwait(false);
        ttfbSw.Stop();

        t.TtfbEnd = baseSw.Elapsed.TotalMilliseconds;

        // Raw TTFB includes DNS/TCP/TLS.
        var rawTtfb = ttfbSw.Elapsed.TotalMilliseconds;

        // Net TTFB attempts to isolate server/proxy latency by subtracting DNS/TCP/TLS setup time.
        t.TtfbRawMs = rawTtfb;
        t.TtfbNetMs = Math.Max(0, rawTtfb - (t.DnsMs + t.TcpMs + t.TlsMs));

        // Transfer: read the full response body to measure download time.
        t.TransferStart = baseSw.Elapsed.TotalMilliseconds;

        var transferSw = Stopwatch.StartNew();
        long bytes = 0;

        await using (var stream = await resp.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false))
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
            try
            {
                while (true)
                {
                    int read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cts.Token).ConfigureAwait(false);
                    if (read <= 0) break;
                    bytes += read;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        transferSw.Stop();
        t.TransferMs = transferSw.Elapsed.TotalMilliseconds;
        t.TransferEnd = baseSw.Elapsed.TotalMilliseconds;

        baseSw.Stop();
        t.TotalMs = baseSw.Elapsed.TotalMilliseconds;
        t.TotalEnd = t.TotalMs;

        // Build output objects.
        var tlsTimings = BuildTlsStepTimings(t);

        var outTimings = new Timings
        {
            Dns = RoundMs(t.DnsMs),
            TcpConnect = RoundMs(t.TcpMs),
            TlsHandshake = RoundMs(t.TlsMs),
            TtfbRaw = RoundMs(t.TtfbRawMs),
            TtfbNet = RoundMs(t.TtfbNetMs),
            Transfer = RoundMs(t.TransferMs),
            Total = RoundMs(t.TotalMs),

            TlsCreateSslStream = RoundMs(tlsTimings.CreateSslStreamMs),
            TlsAuthenticateHandshake = RoundMs(tlsTimings.AuthenticateMs),
            TlsPostHandshakeInspection = RoundMs(tlsTimings.PostHandshakeMs)
        };

        var outWaterfall = new Waterfall
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

        var tlsDetails = BuildTlsDetails(t);
        var ascii = AsciiWaterfallAligned(outWaterfall);

        // Determine warnings.
        var warnings = BuildWarnings(outTimings);

        // CloudWatch logs
        context.Logger.LogLine($"URL: {input.Url}");
        context.Logger.LogLine($"HTTP {(int)resp.StatusCode} | Bytes: {bytes}");

        if (tlsDetails != null)
            LogTlsDetails(context, tlsDetails, outTimings);

        context.Logger.LogLine(ascii);

        foreach (var w in warnings)
            context.Logger.LogLine(w);

        return new Response
        {
            Url = input.Url,
            StatusCode = (int)resp.StatusCode,
            BytesRead = bytes,
            TimingsMs = outTimings,
            Waterfall = outWaterfall,
            TlsDetails = tlsDetails,
            AsciiWaterfall = ascii,
            Warnings = warnings
        };
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

        // Prefer custom chain status when using CustomRootTrust; otherwise use platform chain status.
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
            int s = (int)Math.Round(start / msPerCol);
            int e = (int)Math.Round(end / msPerCol);
            if (e < s) e = s;

            s = Math.Clamp(s, 0, cols);
            e = Math.Clamp(e, 0, cols);

            int barLen = Math.Max(1, e - s);
            int tailSpaces = cols - (s + barLen);

            var sb = new StringBuilder();
            sb.Append(name.PadRight(labelWidth));
            sb.Append(" |");

            if (s > 0) sb.Append(' ', s);
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
    // Helpers: DNS/IP selection
    // -------------------------

    private static IPAddress ChooseIp(IPAddress[] ips)
    {
        // Prefer IPv4 if present, otherwise fall back to the first address.
        foreach (var ip in ips)
            if (ip.AddressFamily == AddressFamily.InterNetwork)
                return ip;
        return ips[0];
    }

    private static double RoundMs(double v) => Math.Round(v, 2);

    // -------------------------
    // Helpers: PEM parsing
    // -------------------------

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

    // -------------------------
    // Helpers: SAN extraction
    // -------------------------

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
                // If SAN extraction fails, do not fail the request.
            }
        }

        return list;
    }

    // -------------------------
    // Internal timing collector
    // -------------------------

    private sealed class TimingCollector
    {
        // Durations
        public double DnsMs, TcpMs, TlsMs, TransferMs, TotalMs;
        public double TtfbRawMs, TtfbNetMs;

        // Offsets
        public double DnsStart, DnsEnd;
        public double TcpStart, TcpEnd;
        public double TlsStart, TlsEnd;
        public double TtfbStart, TtfbEnd;
        public double TransferStart, TransferEnd;
        public double TotalStart, TotalEnd;

        // Coarse TLS internal steps
        public double TlsCreateStreamStart, TlsCreateStreamEnd;
        public double TlsAuthStart, TlsAuthEnd;
        public double TlsPostInfoStart, TlsPostInfoEnd;

        // Negotiated TLS attributes
        public string? NegotiatedProtocol;
        public string? CipherAlgorithm;
        public int CipherStrength;
        public string? HashAlgorithm;
        public int HashStrength;
        public string? KeyExchangeAlgorithm;
        public int KeyExchangeStrength;
        public string? Alpn;

        // Remote certificate
        public string? RemoteCertSubject;
        public string? RemoteCertIssuer;
        public string? RemoteCertThumbprint;
        public string? RemoteCertNotBefore;
        public string? RemoteCertNotAfter;
        public List<string>? RemoteCertSans;

        // Validation diagnostics
        public string? TlsPolicyErrors;
        public string? TlsValidationMode;

        // Chain diagnostics as reported by platform callback (may vary)
        public int PlatformChainElements;
        public List<string>? PlatformChainStatus;

        // Custom chain diagnostics (only for CustomRootTrust)
        public int CustomChainElements;
        public List<string>? CustomChainStatus;
    }
}
