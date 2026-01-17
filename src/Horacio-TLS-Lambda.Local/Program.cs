using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Amazon.Lambda.Core;
using HoracioTLSLambda;

public static class Program
{
    public static async Task Main(string[] args)
    {
        // Minimal CLI parser (no external dependencies)
        var parsed = ParseArgs(args);

        // JSON output is disabled by default for local runs.
        // Enable it only when explicitly requested via --json.
        bool showJson = parsed.ContainsKey("json");

        // URL can be passed as the first positional argument:
        // dotnet run --project ... -- "https://example.com"
        //
        // Or as a named argument:
        // dotnet run --project ... -- --url "https://example.com"
        string url = parsed.TryGetValue("url", out var urlValue)
            ? urlValue
            : (parsed.TryGetValue("_pos0", out var pos0) ? pos0 : "https://example.com");

        string method = parsed.TryGetValue("method", out var m) ? m : "GET";

        int timeoutMs = 15000;
        if (parsed.TryGetValue("timeoutMs", out var t) && int.TryParse(t, out var parsedTimeout))
            timeoutMs = parsedTimeout;

        // Read CA root PEM file (optional)
        string? caRootPem = null;
        if (parsed.TryGetValue("caRootPemFile", out var caPath))
        {
            caRootPem = ReadTextFileOrThrow(caPath);
        }

        // Read intermediate PEM file (optional)
        string? intermediatePem = null;
        if (parsed.TryGetValue("intermediatePemFile", out var interPath))
        {
            intermediatePem = ReadTextFileOrThrow(interPath);
        }

        string revocationMode = parsed.TryGetValue("revocationMode", out var r) ? r : "NoCheck";

        var request = new Request
        {
            Url = url,
            Method = method,
            TimeoutMs = timeoutMs,
            CaRootPem = caRootPem,
            IntermediatePem = intermediatePem,
            RevocationMode = revocationMode
        };


        var fn = new Function();
        var result = await fn.FunctionHandler(request, new LocalLambdaContext());
        
        if (showJson)
        {
            Console.WriteLine();
            Console.WriteLine("===== JSON Output =====");
            Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions
            {
                 WriteIndented = true
            }));
}

    }

    private static string ReadTextFileOrThrow(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("File path cannot be empty.");

        if (!File.Exists(path))
            throw new FileNotFoundException($"File not found: {path}");

        return File.ReadAllText(path);
    }

    private static Dictionary<string, string> ParseArgs(string[] args)
    {
        // Supports:
        // --key value
        // --key=value
        //
        // Also stores positional argument 0 as "_pos0"
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        int posIndex = 0;

        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i]?.Trim();
            if (string.IsNullOrWhiteSpace(a))
                continue;

            if (!a.StartsWith("--"))
            {
                if (posIndex == 0)
                    dict["_pos0"] = a;
                posIndex++;
                continue;
            }

            // Remove leading "--"
            a = a.Substring(2);

            // Handle --key=value
            var eq = a.IndexOf('=');
            if (eq > 0)
            {
                var k = a.Substring(0, eq).Trim();
                var v = a.Substring(eq + 1).Trim().Trim('"');
                dict[k] = v;
                continue;
            }

            // Handle --key value
            var key = a.Trim();
            string value = "";

            if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
            {
                value = args[i + 1].Trim().Trim('"');
                i++;
            }

            dict[key] = value;
        }

        return dict;
    }
}

// Minimal ILambdaContext implementation for local testing
public sealed class LocalLambdaContext : ILambdaContext
{
    public string AwsRequestId => "LOCAL";
    public IClientContext ClientContext => null!;
    public string FunctionName => "Horacio-TLS-Lambda-Local";
    public string FunctionVersion => "LOCAL";
    public ICognitoIdentity Identity => null!;
    public string InvokedFunctionArn => "LOCAL";
    public ILambdaLogger Logger { get; } = new LocalLogger();
    public string LogGroupName => "LOCAL";
    public string LogStreamName => "LOCAL";
    public int MemoryLimitInMB => 512;
    public TimeSpan RemainingTime => TimeSpan.FromMinutes(5);
}

public sealed class LocalLogger : ILambdaLogger
{
    public void Log(string message) => Console.Write(message);
    public void LogLine(string message) => Console.WriteLine(message);
}
