using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing.Session;

static class WindowsFileCollectorSelfTest
{
    private const string SessionName = "OpenSecurityPlatform-FileLifecycle-v1";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static async Task<int> RunAsync(string? output)
    {
        var root = Path.Combine(Path.GetTempPath(), $"platform-windows-file-{Guid.NewGuid():N}");
        var primary = Path.Combine(root, "primary");
        var foreign = Path.Combine(root, "foreign");
        Directory.CreateDirectory(primary);
        Directory.CreateDirectory(foreign);
        var rows = new List<object>();
        try
        {
            await using (var collector = new WindowsEtwFileCollector(primary))
            {
                await collector.StartAsync(default);
                var startup = collector.State == "healthy";
                var probe = Path.Combine(root, "native-probe.txt");
                var childId = 0;
                using (var child = Process.Start(
                    new ProcessStartInfo("cmd.exe", $"/d /c echo native-event>\"{probe}\"")
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    }
                ))
                {
                    childId = child?.Id ?? 0;
                    child?.WaitForExit();
                }
                await Task.Delay(2000);
                var events = await collector.PollAsync(default);
                var childEvents = events.Where(x => x.ProcessId == childId).ToArray();
                var probeObserved = childEvents.Any(x => string.Equals(x.Path, probe, StringComparison.OrdinalIgnoreCase));
                rows.Add(new { name = "elevated-startup-and-native-event", state = collector.State, childProcessId = childId, eventCount = childEvents.Length, observedPaths = childEvents.Select(x => x.Path).Distinct().Take(50), probeObserved, passed = startup && childEvents.Length > 0 && probeObserved });
                await collector.StopAsync(default);
                rows.Add(new { name = "normal-collector-shutdown", state = collector.State, sessionActive = TraceEventSession.GetActiveSessionNames().Contains(SessionName, StringComparer.Ordinal), passed = collector.State == "stopped" && !TraceEventSession.GetActiveSessionNames().Contains(SessionName, StringComparer.Ordinal) });
            }

            await using (var owner = new WindowsEtwFileCollector(primary))
            await using (var conflict = new WindowsEtwFileCollector(foreign))
            {
                await owner.StartAsync(default);
                await conflict.StartAsync(default);
                rows.Add(new { name = "conflicting-third-party-session", state = conflict.State, error = conflict.Error, passed = owner.State == "healthy" && conflict.State == "failed" && conflict.Error?.Contains("not demonstrably platform-owned", StringComparison.Ordinal) == true });
                await owner.StopAsync(default);
                await conflict.StopAsync(default);
            }

            await using (var original = new WindowsEtwFileCollector(primary))
            await using (var recovery = new WindowsEtwFileCollector(primary))
            {
                await original.StartAsync(default);
                await recovery.StartAsync(default);
                rows.Add(new { name = "existing-owned-session-recovery", state = recovery.State, passed = recovery.State == "healthy" });
                await recovery.StopAsync(default);
            }

            var passed = rows.All(x => (bool)(x.GetType().GetProperty("passed")?.GetValue(x) ?? false));
            var report = new { schema = "platform.windows-file-collector-lifecycle.v1", executedAt = DateTimeOffset.UtcNow, platform = Environment.OSVersion.ToString(), elevated = OperatingSystem.IsWindows() && IsElevated(), rows, passed };
            var json = JsonSerializer.Serialize(report, Json);
            Console.WriteLine(json);
            if (!string.IsNullOrWhiteSpace(output))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
                await File.WriteAllTextAsync(output, json);
            }
            return passed ? 0 : 1;
        }
        finally
        {
            try { Directory.Delete(root, true); } catch (IOException) { }
        }
    }

    public static async Task<int> RunPrivilegeAsync(string? output)
    {
        var root = Path.Combine(Path.GetTempPath(), $"platform-windows-file-privilege-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            await using var collector = new WindowsEtwFileCollector(root);
            await collector.StartAsync(default);
            var elevated = OperatingSystem.IsWindows() && IsElevated();
            var passed = !elevated && collector.State == "failed" && collector.Error is not null;
            var report = new { schema = "platform.windows-file-collector-privilege.v1", executedAt = DateTimeOffset.UtcNow, identity = Environment.UserName, elevated, collectorState = collector.State, collectorError = collector.Error, passed };
            var json = JsonSerializer.Serialize(report, Json);
            Console.WriteLine(json);
            if (!string.IsNullOrWhiteSpace(output))
                await File.WriteAllTextAsync(output, json);
            return passed ? 0 : 1;
        }
        finally
        {
            try { Directory.Delete(root, true); } catch (IOException) { }
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsElevated() =>
        new System.Security.Principal.WindowsPrincipal(
            System.Security.Principal.WindowsIdentity.GetCurrent()
        ).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
}
