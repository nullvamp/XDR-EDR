using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

sealed record DurableHashWork(
    Guid WorkId,
    Guid EventId,
    long Sequence,
    string Path,
    string FileEntityId,
    NativeFileSnapshot Before,
    DateTimeOffset RequestedAt,
    string PolicyVersion,
    long MaximumBytes,
    int Attempt = 0
);

sealed record DurableHashCacheEntry(
    string Key,
    FileHashMetadata Value,
    DateTimeOffset LastAccessedAt
);

sealed class FileHashRuntimeMetrics
{
    long _requests,
        _active,
        _successes,
        _failures,
        _skips,
        _oversized,
        _rateLimited,
        _cacheHits,
        _cacheMisses,
        _cacheInvalidations,
        _cacheEvictions,
        _identityMismatches,
        _changed,
        _replaced,
        _deleted,
        _permissionFailures,
        _readFailures,
        _bytesHashed;
    readonly ConcurrentQueue<double> _durations = new();
    readonly ConcurrentQueue<double> _waits = new();

    public void Requested() => Interlocked.Increment(ref _requests);
    public void WorkerStarted() => Interlocked.Increment(ref _active);
    public void WorkerStopped() => Interlocked.Decrement(ref _active);
    public void CacheHit() => Interlocked.Increment(ref _cacheHits);
    public void CacheMiss() => Interlocked.Increment(ref _cacheMisses);
    public void CacheInvalidated() => Interlocked.Increment(ref _cacheInvalidations);
    public void CacheEvicted() => Interlocked.Increment(ref _cacheEvictions);
    public void RateLimited() => Interlocked.Increment(ref _rateLimited);

    public void Completed(FileHashMetadata value, long bytes, double duration, double wait)
    {
        switch (value.State)
        {
            case FileHashState.Succeeded:
                Interlocked.Increment(ref _successes);
                Interlocked.Add(ref _bytesHashed, bytes);
                break;
            case FileHashState.TooLarge:
                Interlocked.Increment(ref _oversized);
                Interlocked.Increment(ref _skips);
                break;
            case FileHashState.RateLimited:
                Interlocked.Increment(ref _rateLimited);
                Interlocked.Increment(ref _skips);
                break;
            case FileHashState.IdentityMismatch:
                Interlocked.Increment(ref _identityMismatches);
                Interlocked.Increment(ref _failures);
                break;
            case FileHashState.ChangedDuringHash:
                Interlocked.Increment(ref _changed);
                Interlocked.Increment(ref _failures);
                break;
            case FileHashState.ReplacedDuringHash:
                Interlocked.Increment(ref _replaced);
                Interlocked.Increment(ref _failures);
                break;
            case FileHashState.DeletedDuringHash:
                Interlocked.Increment(ref _deleted);
                Interlocked.Increment(ref _failures);
                break;
            case FileHashState.PermissionLost:
                Interlocked.Increment(ref _permissionFailures);
                Interlocked.Increment(ref _failures);
                break;
            case FileHashState.ReadFailure:
            case FileHashState.Failed:
            case FileHashState.Unavailable:
                Interlocked.Increment(ref _readFailures);
                Interlocked.Increment(ref _failures);
                break;
            default:
                Interlocked.Increment(ref _skips);
                break;
        }
        Sample(_durations, duration);
        Sample(_waits, wait);
    }

    static void Sample(ConcurrentQueue<double> values, double value)
    {
        values.Enqueue(value);
        while (values.Count > 4096)
            values.TryDequeue(out _);
    }

    public FileHashMetrics Snapshot(string queue)
    {
        var durations = _durations.ToArray();
        var waits = _waits.ToArray();
        Array.Sort(durations);
        Array.Sort(waits);
        var pending = Directory.Exists(queue)
            ? Directory.EnumerateFiles(queue, "*.json").LongCount()
            : 0;
        var oldest = pending == 0
            ? 0
            : Math.Max(
                0,
                (long)(
                    DateTimeOffset.UtcNow
                    - Directory
                        .EnumerateFiles(queue, "*.json")
                        .Select(File.GetCreationTimeUtc)
                        .Min()
                ).TotalSeconds
            );
        return new(
            Interlocked.Read(ref _requests),
            pending,
            oldest,
            Interlocked.Read(ref _active),
            Interlocked.Read(ref _successes),
            Interlocked.Read(ref _failures),
            Interlocked.Read(ref _skips),
            Interlocked.Read(ref _oversized),
            Interlocked.Read(ref _rateLimited),
            Interlocked.Read(ref _cacheHits),
            Interlocked.Read(ref _cacheMisses),
            Interlocked.Read(ref _cacheInvalidations),
            Interlocked.Read(ref _cacheEvictions),
            Interlocked.Read(ref _identityMismatches),
            Interlocked.Read(ref _changed),
            Interlocked.Read(ref _replaced),
            Interlocked.Read(ref _deleted),
            Interlocked.Read(ref _permissionFailures),
            Interlocked.Read(ref _readFailures),
            Interlocked.Read(ref _bytesHashed),
            Mean(durations),
            Percentile(durations, 0.50),
            Percentile(durations, 0.95),
            durations.Length == 0 ? 0 : durations[^1],
            Mean(waits),
            Percentile(waits, 0.95)
        );
    }

    static double Mean(double[] values) => values.Length == 0 ? 0 : values.Average();
    static double Percentile(double[] values, double percentile) =>
        values.Length == 0
            ? 0
            : values[(int)Math.Min(values.Length - 1, Math.Ceiling(values.Length * percentile) - 1)];
}

sealed class DurableFileHashQueue
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    readonly string _workDirectory;
    readonly string _cacheDirectory;
    readonly string _eventQueue;
    readonly string _environment;
    readonly FileHashRuntimeMetrics _metrics = new();
    readonly Queue<DateTimeOffset> _attempts = new();

    public DurableFileHashQueue(string dataDirectory, string eventQueue, string environment)
    {
        _workDirectory = Path.Combine(dataDirectory, "file-hash-work");
        _cacheDirectory = Path.Combine(dataDirectory, "file-hash-cache");
        _eventQueue = eventQueue;
        _environment = environment;
        Directory.CreateDirectory(_workDirectory);
        Directory.CreateDirectory(_cacheDirectory);
        SecureDirectory(_workDirectory);
        SecureDirectory(_cacheDirectory);
        Recover(_workDirectory);
        Recover(_cacheDirectory);
    }

    public FileHashMetrics Metrics => _metrics.Snapshot(_workDirectory);

    public async Task RecoverPendingAsync(long maximumBytes, CancellationToken ct)
    {
        foreach (var path in Directory.EnumerateFiles(_eventQueue, "*.json"))
        {
            FileObservation? observation;
            try
            {
                observation = JsonSerializer.Deserialize<FileObservation>(
                    await File.ReadAllTextAsync(path, ct),
                    Json
                );
            }
            catch (Exception e) when (e is IOException or JsonException)
            {
                continue;
            }
            if (
                observation?.Hash.State != FileHashState.Pending
                || observation.Hash.NativeIdentityBefore is null
                || observation.Hash.SizeAtHash is null
                || observation.Hash.ModifiedAtHash is null
            )
                continue;
            await EnqueueAsync(
                observation,
                new(
                    observation.Hash.NativeIdentityBefore,
                    observation.Hash.SizeAtHash.Value,
                    observation.Hash.ModifiedAtHash.Value,
                    observation.Hash.ChangeTimeAtHash
                ),
                maximumBytes,
                ct
            );
        }
    }

    public async Task EnqueueAsync(
        FileObservation observation,
        NativeFileSnapshot before,
        long maximumBytes,
        CancellationToken ct
    )
    {
        var work = new DurableHashWork(
            observation.EventId,
            observation.EventId,
            observation.Sequence,
            observation.CurrentPath,
            observation.FileEntityId,
            before,
            observation.Hash.RequestedAt ?? DateTimeOffset.UtcNow,
            observation.Hash.PolicyVersion ?? "implicit",
            maximumBytes
        );
        var final = Path.Combine(_workDirectory, $"{work.WorkId:N}.json");
        if (!File.Exists(final))
        {
            await AtomicWriteAsync(final, work, "file-hash-work", ct);
            _metrics.Requested();
        }
    }

    public async Task ProcessAsync(
        string endpointScope,
        int hashesPerMinute,
        int maximumWorkers,
        CancellationToken ct
    )
    {
        var files = Directory
            .EnumerateFiles(_workDirectory, "*.json")
            .OrderBy(File.GetCreationTimeUtc)
            .Take(Math.Clamp(maximumWorkers, 1, 16))
            .ToArray();
        foreach (var file in files)
        {
            var now = DateTimeOffset.UtcNow;
            while (_attempts.TryPeek(out var attempted) && attempted < now.AddMinutes(-1))
                _attempts.Dequeue();
            if (_attempts.Count >= hashesPerMinute)
            {
                await CompleteRateLimitedAsync(file, ct);
                continue;
            }
            _attempts.Enqueue(now);
            await ProcessOneAsync(file, endpointScope, ct);
        }
    }

    async Task CompleteRateLimitedAsync(string workPath, CancellationToken ct)
    {
        DurableHashWork? work;
        try
        {
            work = JsonSerializer.Deserialize<DurableHashWork>(
                await File.ReadAllTextAsync(workPath, ct),
                Json
            );
        }
        catch (Exception e) when (e is IOException or JsonException)
        {
            Quarantine(workPath, e.GetType().Name);
            return;
        }
        if (work is null)
        {
            Quarantine(workPath, "invalid-hash-work");
            return;
        }
        var eventPath = Path.Combine(_eventQueue, $"{work.Sequence:D20}-{work.EventId:N}.json");
        if (!File.Exists(eventPath))
        {
            File.Delete(workPath);
            return;
        }
        var wait = Math.Max(0, (DateTimeOffset.UtcNow - work.RequestedAt).TotalMilliseconds);
        var result = Outcome(work, FileHashState.RateLimited, "policy-rate-limit", work.Before, "skip") with
        {
            QueueWaitMilliseconds = wait,
            DurationMilliseconds = 0,
        };
        await UpdateObservationAsync(eventPath, result, ct);
        File.Delete(workPath);
        _metrics.Completed(result, 0, 0, wait);
    }

    async Task ProcessOneAsync(string workPath, string endpointScope, CancellationToken ct)
    {
        DurableHashWork? work;
        try
        {
            work = JsonSerializer.Deserialize<DurableHashWork>(
                await File.ReadAllTextAsync(workPath, ct),
                Json
            );
        }
        catch (Exception e) when (e is IOException or JsonException)
        {
            Quarantine(workPath, e.GetType().Name);
            return;
        }
        if (work is null)
        {
            Quarantine(workPath, "invalid-hash-work");
            return;
        }
        var eventPath = Path.Combine(
            _eventQueue,
            $"{work.Sequence:D20}-{work.EventId:N}.json"
        );
        if (!File.Exists(eventPath))
        {
            File.Delete(workPath);
            return;
        }
        _metrics.WorkerStarted();
        var timer = Stopwatch.StartNew();
        var wait = Math.Max(0, (DateTimeOffset.UtcNow - work.RequestedAt).TotalMilliseconds);
        FileHashMetadata result;
        long bytes = 0;
        try
        {
            (result, bytes) = await CalculateAsync(work, endpointScope, ct);
            timer.Stop();
            result = result with
            {
                QueueWaitMilliseconds = wait,
                DurationMilliseconds = timer.Elapsed.TotalMilliseconds,
            };
            await UpdateObservationAsync(eventPath, result, ct);
            LocalTestFailpoint.Hit("file-hash-after-event-update", _environment);
            File.Delete(workPath);
            _metrics.Completed(result, bytes, timer.Elapsed.TotalMilliseconds, wait);
        }
        finally
        {
            _metrics.WorkerStopped();
        }
    }

    async Task<(FileHashMetadata Result, long Bytes)> CalculateAsync(
        DurableHashWork work,
        string endpointScope,
        CancellationToken ct
    )
    {
        if (work.Before.Size > work.MaximumBytes)
            return (
                Outcome(work, FileHashState.TooLarge, "policy-size-limit", work.Before, "skip"),
                0
            );
        if (work.Before.Identity.SymbolicLink == true)
            return (
                Outcome(work, FileHashState.Unavailable, "symbolic-link-not-hashed", work.Before, "skip"),
                0
            );
        var pre = NativeFileSnapshotReader.TryRead(work.Path);
        if (pre is null)
            return File.Exists(work.Path)
                ? (Outcome(work, FileHashState.PermissionLost, "identity-read-denied-before-hash", null, "miss"), 0)
                : (Outcome(work, FileHashState.DeletedDuringHash, "deleted-before-hash", null, "miss"), 0);
        if (!work.Before.SameObject(pre))
            return (Outcome(work, FileHashState.ReplacedDuringHash, "identity-replaced-before-hash", pre, "miss"), 0);
        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(work.Path);
            var readable = UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
            if ((mode & readable) == 0)
                return (Outcome(work, FileHashState.PermissionLost, "permission-lost-before-hash", pre, "miss"), 0);
        }
        if (!work.Before.SameState(pre))
            return (Outcome(work, FileHashState.ChangedDuringHash, "changed-before-hash", pre, "miss"), 0);
        var cacheKey = CacheKey(work.Before.CacheMaterial(endpointScope, "sha256"));
        var cachePath = Path.Combine(_cacheDirectory, cacheKey + ".json");
        if (File.Exists(cachePath))
        {
            try
            {
                var cached = JsonSerializer.Deserialize<DurableHashCacheEntry>(
                    await File.ReadAllTextAsync(cachePath, ct),
                    Json
                );
                if (cached is not null && cached.Key == cacheKey)
                {
                    _metrics.CacheHit();
                    File.SetLastWriteTimeUtc(cachePath, DateTime.UtcNow);
                    return (
                        cached.Value with
                        {
                            RequestedAt = work.RequestedAt,
                            PolicyVersion = work.PolicyVersion,
                            CacheResult = "hit",
                        },
                        0
                    );
                }
                _metrics.CacheInvalidated();
                File.Delete(cachePath);
            }
            catch (Exception e) when (e is IOException or JsonException)
            {
                _metrics.CacheInvalidated();
                Quarantine(cachePath, e.GetType().Name);
            }
        }
        _metrics.CacheMiss();
        try
        {
            if (
                _environment != "production"
                && string.Equals(
                    Environment.GetEnvironmentVariable("PLATFORM_FILE_HASH_TEST_READ_FAILURE"),
                    "true",
                    StringComparison.OrdinalIgnoreCase
                )
            )
                throw new IOException("evaluation-only-read-failure");
            await using var stream = new FileStream(
                work.Path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                81920,
                FileOptions.Asynchronous | FileOptions.SequentialScan
            );
            if (
                _environment != "production"
                && int.TryParse(
                    Environment.GetEnvironmentVariable("PLATFORM_FILE_HASH_TEST_DELAY_MS"),
                    out var delay
                )
                && delay is > 0 and <= 30000
            )
                await Task.Delay(delay, ct);
            var value = Convert
                .ToHexString(await SHA256.HashDataAsync(stream, ct))
                .ToLowerInvariant();
            var post = NativeFileSnapshotReader.TryRead(work.Path);
            if (post is null)
                return File.Exists(work.Path)
                    ? (Outcome(work, FileHashState.PermissionLost, "identity-read-denied-after-hash", null, "miss"), 0)
                    : (Outcome(work, FileHashState.DeletedDuringHash, "deleted-during-hash", null, "miss"), 0);
            if (!pre.SameObject(post))
                return (Outcome(work, FileHashState.ReplacedDuringHash, "identity-replaced-during-hash", post, "miss"), 0);
            if (!pre.SameState(post))
                return (Outcome(work, FileHashState.ChangedDuringHash, "changed-during-hash", post, "miss"), 0);
            var result = new FileHashMetadata(
                FileHashState.Succeeded,
                value,
                HashedAt: DateTimeOffset.UtcNow,
                SizeAtHash: post.Size,
                ModifiedAtHash: post.ModifiedAt,
                RequestedAt: work.RequestedAt,
                PolicyVersion: work.PolicyVersion,
                NativeIdentityBefore: pre.Identity,
                NativeIdentityAfter: post.Identity,
                ChangeTimeAtHash: post.ChangedAt,
                CacheResult: "miss",
                SizeAfterHash: post.Size,
                ModifiedAfterHash: post.ModifiedAt,
                ChangeTimeAfterHash: post.ChangedAt
            );
            await AtomicWriteAsync(
                cachePath,
                new DurableHashCacheEntry(cacheKey, result, DateTimeOffset.UtcNow),
                "file-hash-cache",
                ct
            );
            EvictCache();
            return (result, post.Size);
        }
        catch (FileNotFoundException)
        {
            return (Outcome(work, FileHashState.DeletedDuringHash, "deleted-during-hash", null, "miss"), 0);
        }
        catch (UnauthorizedAccessException)
        {
            return (Outcome(work, FileHashState.PermissionLost, "permission-lost", pre, "miss"), 0);
        }
        catch (IOException e)
        {
            if (!OperatingSystem.IsWindows() && File.Exists(work.Path))
            {
                var mode = File.GetUnixFileMode(work.Path);
                var readable = UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
                if ((mode & readable) == 0)
                    return (Outcome(work, FileHashState.PermissionLost, "permission-lost", pre, "miss"), 0);
            }
            return (Outcome(work, FileHashState.ReadFailure, e.GetType().Name, pre, "miss"), 0);
        }
    }

    static FileHashMetadata Outcome(
        DurableHashWork work,
        FileHashState state,
        string reason,
        NativeFileSnapshot? after,
        string cache
    ) =>
        new(
            state,
            FailureReason: reason,
            SizeAtHash: work.Before.Size,
            ModifiedAtHash: work.Before.ModifiedAt,
            RequestedAt: work.RequestedAt,
            PolicyVersion: work.PolicyVersion,
            NativeIdentityBefore: work.Before.Identity,
            NativeIdentityAfter: after?.Identity,
            ChangeTimeAtHash: work.Before.ChangedAt,
            CacheResult: cache,
            SizeAfterHash: after?.Size,
            ModifiedAfterHash: after?.ModifiedAt,
            ChangeTimeAfterHash: after?.ChangedAt
        );

    async Task UpdateObservationAsync(
        string eventPath,
        FileHashMetadata hash,
        CancellationToken ct
    )
    {
        var observation = JsonSerializer.Deserialize<FileObservation>(
                await File.ReadAllTextAsync(eventPath, ct),
                Json
            ) ?? throw new InvalidDataException("Hash target event is invalid.");
        await AtomicWriteAsync(eventPath, observation with { Hash = hash }, "file-hash-event", ct, true);
    }

    async Task AtomicWriteAsync<T>(
        string final,
        T value,
        string failpointPrefix,
        CancellationToken ct,
        bool replace = false
    )
    {
        var tmp = final + ".tmp";
        var committing = final + ".committing";
        if (File.Exists(tmp))
            File.Delete(tmp);
        await using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        {
            await JsonSerializer.SerializeAsync(stream, value, Json, ct);
            LocalTestFailpoint.Hit($"{failpointPrefix}-during-write", _environment);
            await stream.FlushAsync(ct);
            stream.Flush(true);
        }
        LocalTestFailpoint.Hit($"{failpointPrefix}-after-flush", _environment);
        File.Move(tmp, committing, true);
        LocalTestFailpoint.Hit($"{failpointPrefix}-during-rename", _environment);
        File.Move(committing, final, replace);
    }

    static void Recover(string directory)
    {
        foreach (var path in Directory.EnumerateFiles(directory, "*.committing").ToArray())
        {
            var final = path[..^11];
            if (!File.Exists(final))
                File.Move(path, final);
            else
                File.Delete(path);
        }
        foreach (var path in Directory.EnumerateFiles(directory, "*.tmp").ToArray())
            File.Delete(path);
    }

    void EvictCache()
    {
        foreach (var path in Directory.EnumerateFiles(_cacheDirectory, "*.json").OrderBy(File.GetLastWriteTimeUtc).SkipLast(4096).ToArray())
        {
            File.Delete(path);
            _metrics.CacheEvicted();
        }
    }

    static void Quarantine(string path, string reason)
    {
        var directory = Path.Combine(Path.GetDirectoryName(path)!, "quarantine");
        Directory.CreateDirectory(directory);
        SecureDirectory(directory);
        var target = Path.Combine(directory, $"{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.bad");
        try
        {
            File.Move(path, target);
            File.WriteAllText(target + ".reason", reason);
        }
        catch (IOException) { }
    }

    static string CacheKey(string material) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToLowerInvariant();

    static void SecureDirectory(string path)
    {
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            );
    }
}
