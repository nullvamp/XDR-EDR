using System.Net;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing.Session;
using OpenSecurityPlatform.Foundation;

static class DnsCollectorSelfTest
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    public static async Task<int> RunAsync(string dataDirectory, string? output)
    {
        var elevated = OperatingSystem.IsWindows() && IsElevated();
        if (!OperatingSystem.IsWindows() || !elevated) return await Write(output, new { schema = "platform.dns-native-self-test.v1", executedAt = DateTimeOffset.UtcNow, elevated, passed = false, blocker = "elevated-windows-required" }, 2);
        await using var collector = new WindowsDnsClientEtwCollector(dataDirectory); await collector.StartAsync(default);
        if (collector.State != "healthy") return await Write(output, new { schema = "platform.dns-native-self-test.v1", executedAt = DateTimeOffset.UtcNow, elevated, collector = collector.Type, collectorState = collector.State, collectorError = collector.Error, passed = false }, 3);
        Dns.GetHostAddresses("example.com");
        Dns.GetHostAddresses("example.com");
        try { Dns.GetHostAddresses($"sprint6-{Guid.NewGuid():N}.invalid"); } catch (System.Net.Sockets.SocketException) { }
        await Task.Delay(3000); var events = await collector.PollAsync(default); var relevant = events.Where(x => x.QueryName.Contains("example.com", StringComparison.OrdinalIgnoreCase) || x.QueryName.EndsWith(".invalid", StringComparison.OrdinalIgnoreCase)).ToArray();
        await collector.DisposeAsync(); var sessionStopped = !TraceEventSession.GetActiveSessionNames().Contains(WindowsDnsClientEtwCollector.SessionName, StringComparer.Ordinal);
        var queries = relevant.Count(x => x.Kind == DnsEventKind.QueryObserved); var responses = relevant.Count(x => x.Kind == DnsEventKind.ResponseObserved); var failures = relevant.Count(x => x.Kind == DnsEventKind.QueryFailed);
        var passed = relevant.Length > 0 && queries > 0 && (responses > 0 || failures > 0) && relevant.All(x => DnsObservation.TryCanonicalizeName(x.QueryName, out _, out _)) && collector.LostEvents == 0 && sessionStopped;
        return await Write(output, new { schema = "platform.dns-native-self-test.v1", executedAt = DateTimeOffset.UtcNow, elevated, collector = collector.Type, collectorVersion = collector.Version, nativeProvider = "Microsoft-Windows-DNS-Client", providerId = WindowsDnsClientEtwCollector.ProviderId, sessionName = WindowsDnsClientEtwCollector.SessionName, eventCount = relevant.Length, queries, responses, failures, eventIds = relevant.GroupBy(x => x.NativeId).ToDictionary(x => x.Key.ToString(System.Globalization.CultureInfo.InvariantCulture), x => x.Count()), recordTypes = relevant.Select(x => x.RecordType).Where(x => x is not null).Distinct().ToArray(), resolvedAddresses = relevant.SelectMany(x => x.Answers).Select(x => x.ResolvedAddress).Where(x => x is not null).Distinct().ToArray(), processIds = relevant.Select(x => x.ProcessId).Distinct().ToArray(), nativeActivityIds = relevant.Count(x => x.NativeTransactionId is not null), lostEvents = collector.LostEvents, knownLimitations = collector.KnownLimitations, noPacketPayloadCapture = true, sessionStopped, passed }, passed ? 0 : 4);
    }
    static async Task<int> Write(string? output, object report, int code) { var text = JsonSerializer.Serialize(report, Json); Console.WriteLine(text); if (!string.IsNullOrWhiteSpace(output)) { Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!); await File.WriteAllTextAsync(output, text); } return code; }
    [SupportedOSPlatform("windows")] static bool IsElevated() { try { using var identity = WindowsIdentity.GetCurrent(); return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator); } catch { return false; } }
}
