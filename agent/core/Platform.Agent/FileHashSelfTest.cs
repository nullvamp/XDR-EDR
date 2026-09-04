using System.Diagnostics;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

static class FileHashSelfTest
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static async Task<int> RunAsync(string? output)
    {
        var root = Path.Combine(Path.GetTempPath(), "platform-file-hash", Guid.NewGuid().ToString("N"));
        var events = Path.Combine(root, "file-queue");
        Directory.CreateDirectory(events);
        var rows = new List<object>();
        try
        {
            var queue = new DurableFileHashQueue(root, events, "test");
            var stable = Path.Combine(root, "stable.bin");
            await File.WriteAllBytesAsync(stable, new byte[4096]);
            var stableResult = await Execute(queue, events, stable, 1, "tenant:endpoint");
            rows.Add(Row("stable-small", stableResult, FileHashState.Succeeded));

            var medium = Path.Combine(root, "medium.bin");
            await File.WriteAllBytesAsync(medium, new byte[256 * 1024]);
            rows.Add(Row("stable-medium", await Execute(queue, events, medium, 2, "tenant:endpoint"), FileHashState.Succeeded));

            var maximum = Path.Combine(root, "maximum.bin");
            await File.WriteAllBytesAsync(maximum, new byte[2 * 1024 * 1024]);
            rows.Add(Row("maximum-eligible", await Execute(queue, events, maximum, 3, "tenant:endpoint", 2 * 1024 * 1024), FileHashState.Succeeded));

            var oversized = Path.Combine(root, "oversized.bin");
            await File.WriteAllBytesAsync(oversized, new byte[2048]);
            rows.Add(Row("oversized-ineligible", await Execute(queue, events, oversized, 4, "tenant:endpoint", 1024), FileHashState.TooLarge));

            var modifiedBefore = Path.Combine(root, "modified-before.bin");
            await File.WriteAllTextAsync(modifiedBefore, "before");
            var modifiedPending = await Prepare(queue, events, modifiedBefore, 5);
            await File.WriteAllTextAsync(modifiedBefore, "after-value");
            await queue.ProcessAsync("tenant:endpoint", 100, 4, default);
            rows.Add(Row("modified-before-hash", await ReadEvent(events, modifiedPending), FileHashState.ChangedDuringHash));

            var modifiedDuring = Path.Combine(root, "modified-during.bin");
            await File.WriteAllBytesAsync(modifiedDuring, new byte[1024 * 1024]);
            rows.Add(Row("modified-during-hash", await Race(queue, events, modifiedDuring, 6, () => File.WriteAllBytes(modifiedDuring, new byte[1024 * 1024])), FileHashState.ChangedDuringHash));

            var appendDuring = Path.Combine(root, "append-during.bin");
            await File.WriteAllBytesAsync(appendDuring, new byte[1024 * 1024]);
            rows.Add(Row("append-during-hash", await Race(queue, events, appendDuring, 7, () => File.AppendAllText(appendDuring, "append")), FileHashState.ChangedDuringHash));

            var truncateDuring = Path.Combine(root, "truncate-during.bin");
            await File.WriteAllBytesAsync(truncateDuring, new byte[1024 * 1024]);
            rows.Add(Row("truncate-during-hash", await Race(queue, events, truncateDuring, 8, () => { using var stream = new FileStream(truncateDuring, FileMode.Open); stream.SetLength(128); }), FileHashState.ChangedDuringHash));

            var renameDuring = Path.Combine(root, "rename-during.bin");
            await File.WriteAllBytesAsync(renameDuring, new byte[1024 * 1024]);
            rows.Add(Row("rename-during-hash", await Race(queue, events, renameDuring, 9, () => File.Move(renameDuring, renameDuring + ".renamed")), FileHashState.DeletedDuringHash));

            var moveDuring = Path.Combine(root, "move-during.bin");
            var moveDestination = Path.Combine(root, "moved", "move-during.bin");
            Directory.CreateDirectory(Path.GetDirectoryName(moveDestination)!);
            await File.WriteAllBytesAsync(moveDuring, new byte[1024 * 1024]);
            rows.Add(Row("move-during-hash", await Race(queue, events, moveDuring, 10, () => File.Move(moveDuring, moveDestination)), FileHashState.DeletedDuringHash));

            var deleteDuring = Path.Combine(root, "delete-during.bin");
            await File.WriteAllBytesAsync(deleteDuring, new byte[1024 * 1024]);
            rows.Add(Row("delete-during-hash", await Race(queue, events, deleteDuring, 11, () => File.Delete(deleteDuring)), FileHashState.DeletedDuringHash));

            var permission = Path.Combine(root, "permission.bin");
            await File.WriteAllTextAsync(permission, "permission");
            var permissionPending = await Prepare(queue, events, permission, 12);
            if (OperatingSystem.IsWindows())
            {
                using var locked = new FileStream(permission, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                await queue.ProcessAsync("tenant:endpoint", 100, 4, default);
            }
            else
            {
                File.SetUnixFileMode(permission, UnixFileMode.None);
                try
                {
                    await queue.ProcessAsync("tenant:endpoint", 100, 4, default);
                }
                finally
                {
                    File.SetUnixFileMode(permission, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
            }
            rows.Add(Row("permission-removed", await ReadEvent(events, permissionPending), FileHashState.PermissionLost));

            var cacheResult = await Execute(queue, events, stable, 13, "tenant:endpoint");
            rows.Add(
                new
                {
                    name = "cache-hit",
                    expected = FileHashState.Succeeded.ToString(),
                    actual = cacheResult.Hash.State.ToString(),
                    cache = cacheResult.Hash.CacheResult,
                    passed = cacheResult.Hash.State == FileHashState.Succeeded
                        && cacheResult.Hash.CacheResult == "hit",
                }
            );

            var replace = Path.Combine(root, "replace.bin");
            await File.WriteAllTextAsync(replace, "file-a");
            var before = NativeFileSnapshotReader.TryRead(replace)
                ?? throw new InvalidOperationException("Replacement pre-snapshot failed.");
            var pending = Observation(replace, 14, before);
            await WriteEvent(events, pending);
            await queue.EnqueueAsync(pending, before, 16 * 1024 * 1024, default);
            File.Move(replace, replace + ".old");
            await File.WriteAllTextAsync(replace, "file-b");
            await queue.ProcessAsync("tenant:endpoint", 100, 4, default);
            var replacementResult = await ReadEvent(events, pending);
            rows.Add(Row("same-path-replacement", replacementResult, FileHashState.ReplacedDuringHash));
            rows.Add(Row("native-identity-change", replacementResult, FileHashState.ReplacedDuringHash));

            var miss = Path.Combine(root, "cache-miss.bin");
            await File.WriteAllTextAsync(miss, "miss");
            var missResult = await Execute(queue, events, miss, 15, "tenant:endpoint");
            rows.Add(Row("cache-miss", missResult, FileHashState.Succeeded, "miss"));

            await File.AppendAllTextAsync(stable, "invalidate");
            var invalidatedResult = await Execute(queue, events, stable, 16, "tenant:endpoint");
            rows.Add(Row("cache-invalidation", invalidatedResult, FileHashState.Succeeded, "miss"));

            var rateRoot = Path.Combine(root, "rate");
            var rateEvents = Path.Combine(rateRoot, "file-queue");
            Directory.CreateDirectory(rateEvents);
            var rateQueue = new DurableFileHashQueue(rateRoot, rateEvents, "test");
            var rateOne = Path.Combine(rateRoot, "one.bin");
            var rateTwo = Path.Combine(rateRoot, "two.bin");
            await File.WriteAllTextAsync(rateOne, "one");
            await File.WriteAllTextAsync(rateTwo, "two");
            _ = await Prepare(rateQueue, rateEvents, rateOne, 17);
            await Task.Delay(20);
            var ratePending = await Prepare(rateQueue, rateEvents, rateTwo, 18);
            await rateQueue.ProcessAsync("tenant:endpoint", 1, 4, default);
            rows.Add(Row("rate-limit-reached", await ReadEvent(rateEvents, ratePending), FileHashState.RateLimited));

            var disabledSnapshot = NativeFileSnapshotReader.TryRead(stable)!;
            var disabled = Observation(stable, 19, disabledSnapshot) with { Hash = new() };
            rows.Add(Row("hashing-disabled", disabled, FileHashState.NotRequested));

            var restart = Path.Combine(root, "restart.bin");
            await File.WriteAllTextAsync(restart, "restart-safe");
            var restartBefore = NativeFileSnapshotReader.TryRead(restart)
                ?? throw new InvalidOperationException("Restart pre-snapshot failed.");
            var restartPending = Observation(restart, 20, restartBefore);
            await WriteEvent(events, restartPending);
            await queue.EnqueueAsync(restartPending, restartBefore, 16 * 1024 * 1024, default);
            queue = new DurableFileHashQueue(root, events, "test");
            await queue.RecoverPendingAsync(16 * 1024 * 1024, default);
            await queue.ProcessAsync("tenant:endpoint", 100, 4, default);
            var restartResult = await ReadEvent(events, restartPending);
            rows.Add(Row("restart-pending-work", restartResult, FileHashState.Succeeded));

            var readFailure = Path.Combine(root, "read-failure.bin");
            await File.WriteAllTextAsync(readFailure, "read-failure");
            var readPending = await Prepare(queue, events, readFailure, 21);
            Environment.SetEnvironmentVariable("PLATFORM_FILE_HASH_TEST_READ_FAILURE", "true");
            try
            {
                await queue.ProcessAsync("tenant:endpoint", 100, 4, default);
            }
            finally
            {
                Environment.SetEnvironmentVariable("PLATFORM_FILE_HASH_TEST_READ_FAILURE", null);
            }
            rows.Add(Row("read-failure", await ReadEvent(events, readPending), FileHashState.ReadFailure));

            if (!OperatingSystem.IsWindows())
            {
                var symlinkTarget = Path.Combine(root, "symlink-target.bin");
                var symlink = Path.Combine(root, "symlink.bin");
                await File.WriteAllTextAsync(symlinkTarget, "symlink-target");
                File.CreateSymbolicLink(symlink, symlinkTarget);
                rows.Add(Row("symlink-escape-rejected", await Execute(queue, events, symlink, 22, "tenant:endpoint"), FileHashState.Unavailable));

                var hardTarget = Path.Combine(root, "hard-target.bin");
                var hardLink = Path.Combine(root, "hard-link.bin");
                await File.WriteAllTextAsync(hardTarget, "same-native-object");
                using (var linker = Process.Start(new ProcessStartInfo("ln", [hardTarget, hardLink]) { UseShellExecute = false }))
                {
                    if (linker is null)
                        throw new IOException("Hard-link fixture process failed to start.");
                    await linker.WaitForExitAsync();
                    if (linker.ExitCode != 0)
                        throw new IOException($"Hard-link fixture failed with exit {linker.ExitCode}.");
                }
                var targetResult = await Execute(queue, events, hardTarget, 23, "tenant:endpoint");
                var linkResult = await Execute(queue, events, hardLink, 24, "tenant:endpoint");
                rows.Add(
                    new
                    {
                        name = "hard-link-native-identity",
                        targetIdentity = targetResult.Hash.NativeIdentityAfter,
                        linkIdentity = linkResult.Hash.NativeIdentityAfter,
                        cache = linkResult.Hash.CacheResult,
                        passed = targetResult.Hash.State == FileHashState.Succeeded
                            && linkResult.Hash.State == FileHashState.Succeeded
                            && targetResult.Hash.NativeIdentityAfter == linkResult.Hash.NativeIdentityAfter
                            && linkResult.Hash.CacheResult == "hit",
                    }
                );
            }

            var metrics = queue.Metrics;
            var passed = rows.All(x =>
                (bool)(x.GetType().GetProperty("passed")?.GetValue(x) ?? false)
            );
            var report = new
            {
                schema = "platform.file-hash-self-test.v1",
                executedAt = DateTimeOffset.UtcNow,
                passed,
                cases = rows,
                metrics,
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
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, true);
        }
    }

    static object Row(
        string name,
        FileObservation actual,
        FileHashState expected,
        string? expectedCache = null
    ) =>
        new
        {
            name,
            expected = expected.ToString(),
            actual = actual.Hash.State.ToString(),
            nativeIdentityBefore = actual.Hash.NativeIdentityBefore,
            nativeIdentityAfter = actual.Hash.NativeIdentityAfter,
            actual.Hash.FailureReason,
            actual.Hash.CacheResult,
            actual.Hash.QueueWaitMilliseconds,
            actual.Hash.DurationMilliseconds,
            pathBefore = actual.OriginalPath,
            pathAfter = actual.CurrentPath,
            sizeBefore = actual.Hash.SizeAtHash,
            sizeAfter = actual.Hash.SizeAfterHash,
            modifiedBefore = actual.Hash.ModifiedAtHash,
            modifiedAfter = actual.Hash.ModifiedAfterHash,
            actual.Hash.PolicyVersion,
            passed = actual.Hash.State == expected
                && (expectedCache is null || actual.Hash.CacheResult == expectedCache),
        };

    static async Task<FileObservation> Execute(
        DurableFileHashQueue queue,
        string events,
        string path,
        long sequence,
        string scope,
        long maximumBytes = 16 * 1024 * 1024
    )
    {
        var snapshot = NativeFileSnapshotReader.TryRead(path)
            ?? throw new InvalidOperationException("Native snapshot failed.");
        var observation = Observation(path, sequence, snapshot);
        await WriteEvent(events, observation);
        await queue.EnqueueAsync(observation, snapshot, maximumBytes, default);
        await queue.ProcessAsync(scope, 100, 4, default);
        return await ReadEvent(events, observation);
    }

    static async Task<FileObservation> Prepare(
        DurableFileHashQueue queue,
        string events,
        string path,
        long sequence
    )
    {
        var snapshot = NativeFileSnapshotReader.TryRead(path)
            ?? throw new InvalidOperationException("Native snapshot failed.");
        var observation = Observation(path, sequence, snapshot);
        await WriteEvent(events, observation);
        await queue.EnqueueAsync(observation, snapshot, 16 * 1024 * 1024, default);
        return observation;
    }

    static async Task<FileObservation> Race(
        DurableFileHashQueue queue,
        string events,
        string path,
        long sequence,
        Action mutation
    )
    {
        var pending = await Prepare(queue, events, path, sequence);
        Environment.SetEnvironmentVariable("PLATFORM_FILE_HASH_TEST_DELAY_MS", "150");
        var mutationTask = Task.Run(async () =>
        {
            await Task.Delay(30);
            mutation();
        });
        try
        {
            await queue.ProcessAsync("tenant:endpoint", 100, 4, default);
            await mutationTask;
        }
        finally
        {
            Environment.SetEnvironmentVariable("PLATFORM_FILE_HASH_TEST_DELAY_MS", null);
        }
        return await ReadEvent(events, pending);
    }

    internal static FileObservation Observation(string path, long sequence, NativeFileSnapshot snapshot)
    {
        var endpoint = Guid.Parse("10000000-0000-0000-0000-000000000001");
        var eventId = Guid.NewGuid();
        return new(
            eventId,
            "file-event.v1",
            FileEventKind.Created,
            endpoint,
            Guid.Parse("20000000-0000-0000-0000-000000000002"),
            "hash-self-test",
            "hash-self-test",
            "local-test",
            "1.0",
            OperatingSystem.IsWindows() ? "windows" : "linux",
            eventId.ToString("N"),
            sequence,
            DateTimeOffset.UtcNow,
            "file-normalization.v1",
            null,
            null,
            null,
            [],
            "high",
            FileObservation.StableEntityId(endpoint, snapshot.Identity, path, DateTimeOffset.UtcNow),
            snapshot.Identity,
            path,
            path,
            null,
            null,
            Path.GetFileName(path),
            Path.GetDirectoryName(path)!,
            Path.GetExtension(path).TrimStart('.'),
            "absolute",
            "preserved",
            !OperatingSystem.IsWindows(),
            null,
            false,
            null,
            new(snapshot.Size, null, snapshot.ModifiedAt, null, null, null, null, null, null, null, null, null, null),
            new(
                FileHashState.Pending,
                RequestedAt: DateTimeOffset.UtcNow,
                PolicyVersion: "hash-self-test:1",
                SizeAtHash: snapshot.Size,
                ModifiedAtHash: snapshot.ModifiedAt,
                NativeIdentityBefore: snapshot.Identity,
                ChangeTimeAtHash: snapshot.ChangedAt,
                CacheResult: "pending"
            ),
            null,
            null,
            null,
            "success",
            "self-test"
        );
    }

    internal static async Task WriteEvent(string events, FileObservation observation) =>
        await File.WriteAllTextAsync(
            Path.Combine(events, $"{observation.Sequence:D20}-{observation.EventId:N}.json"),
            JsonSerializer.Serialize(observation, Json)
        );

    internal static async Task<FileObservation> ReadEvent(string events, FileObservation observation) =>
        JsonSerializer.Deserialize<FileObservation>(
            await File.ReadAllTextAsync(
                Path.Combine(events, $"{observation.Sequence:D20}-{observation.EventId:N}.json")
            ),
            Json
        ) ?? throw new InvalidDataException("Hash self-test result is invalid.");
}
