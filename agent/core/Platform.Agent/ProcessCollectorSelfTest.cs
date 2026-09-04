using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

static class ProcessCollectorSelfTest
{
    private static readonly JsonSerializerOptions ReportJson = new() { WriteIndented = true };

    public static async Task<int> RunAsync()
    {
        await using IProcessCollector collector =
            OperatingSystem.IsWindows() ? new WindowsEtwProcessCollector()
            : OperatingSystem.IsLinux() ? ProcessCollectorFactory.Create(AgentOptions.Load())
            : new MacEndpointSecurityProcessCollector(
                Environment.GetEnvironmentVariable("PLATFORM_MACOS_ES_JSON_PATH")
                    ?? "/Library/Application Support/OpenSecurityPlatform/process-events.jsonl"
            );
        var count = Int("PLATFORM_PROCESS_TEST_COUNT", 4, 1, 5000);
        var concurrency = Int("PLATFORM_PROCESS_TEST_CONCURRENCY", 1, 1, 128);
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        await collector.StartAsync(timeout.Token);
        if (!collector.Health.State.StartsWith("healthy", StringComparison.Ordinal))
        {
            Console.Error.WriteLine(
                JsonSerializer.Serialize(new { collector.Type, collector.Health })
            );
            return 2;
        }

        var expected = new ConcurrentBag<ExpectedProcess>();
        var pids = new ConcurrentDictionary<int, byte>();
        using var gate = new SemaphoreSlim(concurrency);
        await Task.WhenAll(
            Enumerable
                .Range(0, count)
                .Select(async index =>
                {
                    await gate.WaitAsync(timeout.Token);
                    try
                    {
                        var lifetime = new[] { 0, 25, 100, 500, 1000 }[index % 5];
                        var started = DateTimeOffset.UtcNow;
                        using var process = Start(lifetime);
                        pids.TryAdd(process.Id, 0);
                        await process.WaitForExitAsync(timeout.Token);
                        expected.Add(
                            new(
                                process.Id,
                                lifetime,
                                started,
                                DateTimeOffset.UtcNow,
                                process.ExitCode
                            )
                        );
                    }
                    finally
                    {
                        gate.Release();
                    }
                })
        );
        await Task.Delay(TimeSpan.FromSeconds(Math.Min(15, 3 + count / 100)), timeout.Token);
        // Collectors expose bounded pages so normal agent polling cannot monopolize a
        // worker. The self-test must drain those pages; a single poll would mostly
        // contain startup inventory on busy hosts and falsely report lifecycle loss.
        var observed = new List<NativeProcessEvent>();
        var maximumPages = Math.Max(4, ((count * 2 + 4096) / 250) + 2);
        for (var page = 0; page < maximumPages; page++)
        {
            var batch = await collector.PollAsync(timeout.Token);
            observed.AddRange(batch);
            if (batch.Count < 250)
                break;
        }
        await collector.StopAsync(timeout.Token);
        var expectedValues = expected.OrderBy(x => x.Started).ToArray();
        var lower = expectedValues.Min(x => x.Started).AddSeconds(-1);
        var upper = expectedValues.Max(x => x.Exited).AddSeconds(5);
        var starts = observed
            .Where(x =>
                pids.ContainsKey(x.Pid)
                && x.Kind == ProcessEventKind.Started
                && x.ObservedAt >= lower
                && x.ObservedAt <= upper
            )
            .ToArray();
        var exits = observed
            .Where(x =>
                pids.ContainsKey(x.Pid)
                && x.Kind == ProcessEventKind.Exited
                && x.ObservedAt >= lower
                && x.ObservedAt <= upper
            )
            .ToArray();
        var usedStarts = new HashSet<string>(StringComparer.Ordinal);
        var matchedStarts = new List<NativeProcessEvent>();
        var matchedExits = new List<NativeProcessEvent>();
        var missingStarts = new List<string>();
        var missingExits = new List<string>();
        foreach (var item in expectedValues)
        {
            var start = starts
                .Where(x =>
                    x.Pid == item.Id
                    && x.NativeSourceEventId is not null
                    && !usedStarts.Contains(x.NativeSourceEventId)
                )
                .OrderBy(x => Math.Abs((x.StartTime - item.Started).TotalMilliseconds))
                .FirstOrDefault();
            if (start is null)
            {
                missingStarts.Add($"{item.Id}@{item.Started:O}");
                continue;
            }
            usedStarts.Add(start.NativeSourceEventId!);
            matchedStarts.Add(start);
            var exit = exits.FirstOrDefault(x => x.Pid == item.Id && x.StartKey == start.StartKey);
            if (exit is null)
                missingExits.Add($"{item.Id}@{item.Started:O}");
            else
                matchedExits.Add(exit);
        }
        var result = new
        {
            collector = new
            {
                collector.Type,
                collector.Version,
                collector.SourceType,
            },
            expected = expectedValues,
            concurrency,
            expectedStarts = expectedValues.Length,
            expectedExits = expectedValues.Length,
            observedStarts = matchedStarts.Count,
            observedExits = matchedExits.Count,
            rawCandidateStarts = starts.Length,
            rawCandidateExits = exits.Length,
            paired = matchedExits.Count,
            parentResolved = matchedStarts.Count(x => x.ParentPid == Environment.ProcessId),
            missingStarts,
            missingExits,
            duplicateStarts = starts
                .Where(x => x.NativeSourceEventId is not null)
                .GroupBy(x => x.NativeSourceEventId)
                .Count(x => x.Count() > 1),
            duplicateExits = exits
                .Where(x => x.NativeSourceEventId is not null)
                .GroupBy(x => x.NativeSourceEventId)
                .Count(x => x.Count() > 1),
            collector.Health,
        };
        Console.WriteLine(JsonSerializer.Serialize(result, ReportJson));
        return
            matchedStarts.Count == expectedValues.Length
            && matchedExits.Count == expectedValues.Length
            ? 0
            : 1;
    }

    private static Process Start(int lifetimeMilliseconds)
    {
        if (OperatingSystem.IsWindows())
        {
            if (
                Environment.GetEnvironmentVariable("PLATFORM_PROCESS_GENERATOR_PATH") is
                { Length: > 0 } generator
            )
                return Process.Start(
                        new ProcessStartInfo(
                            generator,
                            $"--child --lifetime-ms {lifetimeMilliseconds} --exit-code 0 --marker sprint2d"
                        )
                        {
                            UseShellExecute = false,
                            CreateNoWindow = true,
                        }
                    ) ?? throw new InvalidOperationException("Process generator failed.");
            return Process.Start(
                    new ProcessStartInfo(
                        Environment.GetEnvironmentVariable("ComSpec") ?? "cmd.exe",
                        $"/d /s /c \"ping -n 1 127.0.0.1 >nul & powershell -NoProfile -Command Start-Sleep -Milliseconds {lifetimeMilliseconds}\""
                    )
                    {
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    }
                ) ?? throw new InvalidOperationException("Process generator failed.");
        }
        return Process.Start(
                new ProcessStartInfo("sh", $"-c \"sleep {lifetimeMilliseconds / 1000.0:F3}\"")
                {
                    UseShellExecute = false,
                }
            ) ?? throw new InvalidOperationException("Process generator failed.");
    }

    private static int Int(string name, int fallback, int minimum, int maximum) =>
        int.TryParse(Environment.GetEnvironmentVariable(name), out var value)
            ? Math.Clamp(value, minimum, maximum)
            : fallback;

    private sealed record ExpectedProcess(
        int Id,
        int Lifetime,
        DateTimeOffset Started,
        DateTimeOffset Exited,
        int ExitCode
    );
}
