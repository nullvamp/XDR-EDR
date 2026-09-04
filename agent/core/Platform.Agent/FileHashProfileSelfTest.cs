using System.Diagnostics;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

static class FileHashProfileSelfTest
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    sealed record ProfileDefinition(string Name, int Count, int Size, string Kind, int Rate = 10000);

    public static async Task<int> RunAsync(string? output)
    {
        ProfileDefinition[] definitions =
        [
            new("H1", 0, 0, "disabled"),
            new("H2", 160, 4 * 1024, "unique"),
            new("H3", 32, 1024 * 1024, "unique"),
            new("H4", 8, 16 * 1024 * 1024, "unique"),
            new("H5", 160, 64 * 1024, "cache-heavy"),
            new("H6", 160, 64 * 1024, "unique"),
            new("H7", 24, 64 * 1024, "unique", 4),
            new("H8", 16, 2 * 1024 * 1024, "race"),
        ];
        var rows = new List<object>();
        foreach (var definition in definitions)
            rows.Add(await RunProfile(definition));
        var passed = rows.All(row => (bool)(row.GetType().GetProperty("passed")?.GetValue(row) ?? false));
        var report = new
        {
            schema = "platform.file-hash-profiles.v1",
            executedAt = DateTimeOffset.UtcNow,
            platform = Environment.OSVersion.ToString(),
            processorCount = Environment.ProcessorCount,
            passed,
            profiles = rows,
        };
        var text = JsonSerializer.Serialize(report, Json);
        Console.WriteLine(text);
        if (!string.IsNullOrWhiteSpace(output))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            await File.WriteAllTextAsync(output, text);
        }
        return passed ? 0 : 1;
    }

    static async Task<object> RunProfile(ProfileDefinition definition)
    {
        var root = Path.Combine(Path.GetTempPath(), "platform-hash-profile", definition.Name + "-" + Guid.NewGuid().ToString("N"));
        var events = Path.Combine(root, "file-queue");
        var probes = Path.Combine(root, "primary-probes");
        Directory.CreateDirectory(events);
        Directory.CreateDirectory(probes);
        try
        {
            var queue = new DurableFileHashQueue(root, events, "test");
            var observations = new List<FileObservation>();
            string? shared = null;
            if (definition.Kind == "cache-heavy")
            {
                shared = Path.Combine(root, "shared.bin");
                await WriteSizedFile(shared, definition.Size, 17);
            }
            for (var i = 0; i < definition.Count; i++)
            {
                var path = shared ?? Path.Combine(root, $"input-{i:D4}.bin");
                if (shared is null)
                    await WriteSizedFile(path, definition.Size, i + 1);
                var snapshot = NativeFileSnapshotReader.TryRead(path)
                    ?? throw new InvalidOperationException($"Native snapshot failed for {definition.Name}.");
                var observation = FileHashSelfTest.Observation(path, i + 1, snapshot) with
                {
                    Hash = FileHashSelfTest.Observation(path, i + 1, snapshot).Hash with
                    {
                        PolicyVersion = $"profile:{definition.Name}",
                    },
                };
                await FileHashSelfTest.WriteEvent(events, observation);
                await queue.EnqueueAsync(observation, snapshot, 16 * 1024 * 1024, default);
                observations.Add(observation);
            }

            var pendingBefore = queue.Metrics.Pending;
            var oldestBefore = queue.Metrics.OldestPendingSeconds;
            var process = Process.GetCurrentProcess();
            var samples = new List<(double Cpu, long Memory, long Active, long Pending)>();
            var probeLatencies = new List<double>();
            var cpuBefore = process.TotalProcessorTime;
            var wall = Stopwatch.StartNew();
            var previousCpu = cpuBefore;
            var previousAt = Stopwatch.StartNew();
            var workload = definition.Kind == "disabled"
                ? Task.Delay(500)
                : ProcessAll(queue, definition, observations);
            var probeTask = Task.Run(async () =>
            {
                for (var i = 0; i < 25; i++)
                {
                    var timer = Stopwatch.StartNew();
                    await File.WriteAllTextAsync(Path.Combine(probes, $"probe-{i:D2}.json"), "{\"schema\":\"probe.v1\"}");
                    timer.Stop();
                    lock (probeLatencies)
                        probeLatencies.Add(timer.Elapsed.TotalMilliseconds);
                    await Task.Delay(10);
                }
            });
            while (!workload.IsCompleted || !probeTask.IsCompleted)
            {
                await Task.Delay(25);
                process.Refresh();
                var intervalSeconds = Math.Max(0.001, previousAt.Elapsed.TotalSeconds);
                var currentCpu = process.TotalProcessorTime;
                var cpu = Math.Max(0, (currentCpu - previousCpu).TotalSeconds / intervalSeconds / Environment.ProcessorCount * 100);
                var metrics = queue.Metrics;
                samples.Add((cpu, process.WorkingSet64, metrics.ActiveWorkers, metrics.Pending));
                previousCpu = currentCpu;
                previousAt.Restart();
            }
            await Task.WhenAll(workload, probeTask);
            wall.Stop();
            process.Refresh();
            var metricsAfter = queue.Metrics;
            var totalCpu = (process.TotalProcessorTime - cpuBefore).TotalSeconds / Math.Max(0.001, wall.Elapsed.TotalSeconds) / Environment.ProcessorCount * 100;
            var sortedProbe = probeLatencies.Order().ToArray();
            var raceDetections = metricsAfter.IdentityMismatches + metricsAfter.ChangedDuringHash + metricsAfter.ReplacedDuringHash + metricsAfter.DeletedDuringHash;
            var passed = definition.Kind switch
            {
                "disabled" => metricsAfter.Requests == 0 && metricsAfter.Pending == 0,
                "cache-heavy" => metricsAfter.Successes == definition.Count && metricsAfter.CacheHits >= definition.Count - 1,
                "race" => metricsAfter.Requests == definition.Count && raceDetections > 0 && metricsAfter.Pending == 0,
                _ when definition.Name == "H7" => metricsAfter.RateLimited > 0 && metricsAfter.Pending == 0,
                _ => metricsAfter.Successes == definition.Count && metricsAfter.Pending == 0,
            };
            var expectedProbes = 25;
            var actualProbes = Directory.EnumerateFiles(probes, "*.json").Count();
            passed = passed && actualProbes == expectedProbes;
            return new
            {
                profile = definition.Name,
                workload = definition.Kind,
                files = definition.Count,
                bytesPerFile = definition.Size,
                elapsedMilliseconds = wall.Elapsed.TotalMilliseconds,
                agentCpuMeanPercent = totalCpu,
                agentCpuPeakPercent = samples.Count == 0 ? totalCpu : samples.Max(x => x.Cpu),
                agentMemoryMeanBytes = samples.Count == 0 ? process.WorkingSet64 : samples.Average(x => (double)x.Memory),
                agentMemoryPeakBytes = samples.Count == 0 ? process.WorkingSet64 : samples.Max(x => x.Memory),
                hashWorkersPeak = samples.Count == 0 ? 0 : samples.Max(x => x.Active),
                hashQueuePeak = Math.Max(pendingBefore, samples.Count == 0 ? 0 : samples.Max(x => x.Pending)),
                oldestHashAgeSeconds = Math.Max(oldestBefore, metricsAfter.OldestPendingSeconds),
                metrics = metricsAfter,
                raceDetections,
                throughputFilesPerSecond = definition.Count == 0 ? 0 : definition.Count / Math.Max(0.001, wall.Elapsed.TotalSeconds),
                fileEventQueue = new { before = definition.Count, peak = definition.Count, after = definition.Count, hashHeadOfLineBlocking = false },
                ingestionLatencyMilliseconds = new
                {
                    mean = sortedProbe.Length == 0 ? 0 : sortedProbe.Average(),
                    p50 = Percentile(sortedProbe, .50),
                    p95 = Percentile(sortedProbe, .95),
                    maximum = sortedProbe.Length == 0 ? 0 : sortedProbe[^1],
                },
                loss = new { expected = expectedProbes, persisted = actualProbes, unexplained = expectedProbes - actualProbes },
                passed,
            };
        }
        finally
        {
            Environment.SetEnvironmentVariable("PLATFORM_FILE_HASH_TEST_DELAY_MS", null);
            if (Directory.Exists(root))
                Directory.Delete(root, true);
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }
    }

    static async Task ProcessAll(DurableFileHashQueue queue, ProfileDefinition definition, IReadOnlyList<FileObservation> observations)
    {
        Task? mutation = null;
        if (definition.Kind == "race")
        {
            Environment.SetEnvironmentVariable("PLATFORM_FILE_HASH_TEST_DELAY_MS", "100");
            mutation = Task.Run(async () =>
            {
                await Task.Delay(25);
                foreach (var observation in observations)
                    await File.AppendAllTextAsync(observation.CurrentPath, "race");
            });
        }
        while (queue.Metrics.Pending > 0)
            await queue.ProcessAsync("tenant:endpoint", definition.Rate, 4, default);
        if (mutation is not null)
            await mutation;
    }

    static async Task WriteSizedFile(string path, int size, int seed)
    {
        var buffer = new byte[size];
        new Random(seed).NextBytes(buffer);
        await File.WriteAllBytesAsync(path, buffer);
    }

    static double Percentile(double[] values, double percentile) =>
        values.Length == 0 ? 0 : values[(int)Math.Min(values.Length - 1, Math.Ceiling(values.Length * percentile) - 1)];
}
