// File: src/Horacio-TLS-Lambda/Program.cs
// Purpose: Optional console runner inside the Lambda project (debug harness)

using System;
using System.Text.Json;
using System.Threading.Tasks;
using Amazon.Lambda.Core;

namespace HoracioTLSLambda;

public static class Program
{
    public static async Task Main(string[] args)
    {
        var url = args.Length > 0 ? args[0] : "https://example.com";

        var request = new Request
        {
            Url = url,
            Method = "GET",
            TimeoutMs = 15000,
            CaRootPem = "",
            IntermediatePem = ""
        };

        var fn = new Function();
        var result = await fn.FunctionHandler(request, new LocalLambdaContext());

        Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
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
