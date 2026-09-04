using System.Text.Json;

static class CredentialStoreSelfTest
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static async Task<int> RunAsync(string? output)
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            $"platform-credential-store-{Guid.NewGuid():N}"
        );
        Directory.CreateDirectory(root);
        try
        {
            using var store = new FileCredentialStore(root, OperatingSystem.IsWindows());
            var template = new AgentState(
                Guid.NewGuid(),
                Guid.NewGuid(),
                Guid.NewGuid().ToString("N"),
                Convert.ToBase64String([1, 2, 3]),
                "test-ca",
                DateTimeOffset.UtcNow.AddHours(1),
                0
            );
            const int writers = 64;
            using var readsDone = new CancellationTokenSource();
            var reader = Task.Run(async () =>
            {
                while (!readsDone.IsCancellationRequested)
                {
                    _ = await store.LoadAsync(default);
                    await Task.Yield();
                }
            });
            await Task.WhenAll(
                Enumerable.Range(1, writers).Select(x => store.SaveAsync(template with { Sequence = x }, default))
            );
            readsDone.Cancel();
            await reader;
            var restored = await store.LoadAsync(default);
            var temporaryFileRemaining = Directory
                .EnumerateFiles(root, "state.dat.*.tmp")
                .Any();
            var passed = restored is not null
                && restored.Sequence is >= 1 and <= writers
                && File.Exists(Path.Combine(root, "state.dat"))
                && !temporaryFileRemaining;
            var report = new
            {
                schema = "platform.credential-store-concurrency.v1",
                executedAt = DateTimeOffset.UtcNow,
                platform = Environment.OSVersion.ToString(),
                dpapi = OperatingSystem.IsWindows(),
                concurrentWriters = writers,
                restoredSequence = restored?.Sequence,
                temporaryFileRemaining,
                passed,
            };
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
            Directory.Delete(root, true);
        }
    }
}
