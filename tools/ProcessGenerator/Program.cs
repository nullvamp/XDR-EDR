using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32;

static int Arg(string[] values, string name, int fallback) =>
    Array.IndexOf(values, name) is var index
    && index >= 0
    && index + 1 < values.Length
    && int.TryParse(values[index + 1], out var parsed)
        ? parsed
        : fallback;

static string? TextArg(string[] values, string name) =>
    Array.IndexOf(values, name) is var index && index >= 0 && index + 1 < values.Length
        ? values[index + 1]
        : null;

if (args.Contains("--tree-node", StringComparer.Ordinal))
{
    var depth = Math.Clamp(Arg(args, "--depth", 0), 0, 8);
    var manifestPath = TextArg(args, "--manifest") ?? throw new ArgumentException("--manifest is required");
    var started = new DateTimeOffset(Process.GetCurrentProcess().StartTime.ToUniversalTime());
    await File.AppendAllTextAsync(manifestPath, JsonSerializer.Serialize(new { depth, pid = Environment.ProcessId, startTime = started, imagePath = Environment.ProcessPath }) + Environment.NewLine);
    Process? treeChild = null;
    if (depth > 0)
    {
        treeChild = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, $"--tree-node --depth {depth - 1} --manifest \"{manifestPath}\" --lifetime-ms {Arg(args, "--lifetime-ms", 60000)}") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true });
    }
    await Task.Delay(Arg(args, "--lifetime-ms", 60000));
    treeChild?.Dispose();
    return 0;
}

[SupportedOSPlatform("windows")]
static void RegistryWorkload(string path, string valueName, string kind)
{
    using var key = Registry.CurrentUser.CreateSubKey(path, true);
    if (kind == "binary")
        key.SetValue(valueName, Enumerable.Range(0, 512).Select(x => (byte)(x % 251)).ToArray(), RegistryValueKind.Binary);
    else
        key.SetValue(valueName, TextArg(Environment.GetCommandLineArgs(), "--registry-data") ?? "controlled-process-relationship", RegistryValueKind.String);
}

if (args.Contains("--child", StringComparer.Ordinal))
{
    if (TextArg(args, "--registry-path") is { Length: > 0 } registryPath)
    {
        if (!OperatingSystem.IsWindows())
            return 2;
        RegistryWorkload(registryPath, TextArg(args, "--registry-value") ?? "ProcessValue", TextArg(args, "--registry-kind") ?? "string");
    }
    var childLifetime = Arg(args, "--lifetime-ms", 100);
    if (TextArg(args, "--heartbeat") is { } heartbeat)
    {
        var until = DateTimeOffset.UtcNow.AddMilliseconds(childLifetime);
        while (DateTimeOffset.UtcNow < until) { await File.AppendAllTextAsync(heartbeat, DateTimeOffset.UtcNow.ToString("O") + Environment.NewLine); await Task.Delay(100); }
    }
    else await Task.Delay(childLifetime);
    return Arg(args, "--exit-code", 0);
}

var count = Math.Clamp(Arg(args, "--count", 1), 1, 10000);
var concurrency = Math.Clamp(Arg(args, "--concurrency", 1), 1, 128);
var lifetime = Math.Clamp(Arg(args, "--lifetime-ms", 100), 0, 60000);
var exitCode = Math.Clamp(Arg(args, "--exit-code", 0), 0, 255);
var executable =
    Environment.ProcessPath
    ?? throw new InvalidOperationException("Generator executable path unavailable.");
var records = new List<object>();
using var gate = new SemaphoreSlim(concurrency);
var tasks = Enumerable
    .Range(0, count)
    .Select(async index =>
    {
        await gate.WaitAsync();
        try
        {
            var expectedStart = DateTimeOffset.UtcNow;
            using var process =
                Process.Start(
                    new ProcessStartInfo(
                        executable,
                        $"--child --lifetime-ms {lifetime} --exit-code {exitCode} --marker unicode-مرحبا-{index}"
                    )
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    }
                ) ?? throw new InvalidOperationException("Child process failed to start.");
            var pid = process.Id;
            await process.WaitForExitAsync();
            lock (records)
                records.Add(
                    new
                    {
                        index,
                        pid,
                        parentPid = Environment.ProcessId,
                        expectedStart,
                        expectedExit = DateTimeOffset.UtcNow,
                        lifetimeMilliseconds = lifetime,
                        exitCode = process.ExitCode,
                        marker = $"unicode-مرحبا-{index}",
                    }
                );
        }
        finally
        {
            gate.Release();
        }
    })
    .ToArray();
await Task.WhenAll(tasks);
var manifest = new
{
    schema = "platform.process-generator-manifest.v1",
    generatedAt = DateTimeOffset.UtcNow,
    expectedStarts = count,
    expectedExits = count,
    concurrency,
    records = records.OrderBy(x => JsonSerializer.Serialize(x)).ToArray(),
};
Console.WriteLine(JsonSerializer.Serialize(manifest));
return 0;
