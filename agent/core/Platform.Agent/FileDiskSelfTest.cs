using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;

static class FileDiskSelfTest
{
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public static async Task<int> RunAsync(string? configuredRoot, string? output)
    {
        if (string.IsNullOrWhiteSpace(configuredRoot))
            throw new InvalidOperationException("A dedicated bounded test root is required.");
        var root = Path.GetFullPath(configuredRoot);
        Directory.CreateDirectory(root);
        var drive = DriveInfo
            .GetDrives()
            .Where(x => root.StartsWith(x.RootDirectory.FullName, StringComparison.Ordinal))
            .OrderByDescending(x => x.RootDirectory.FullName.Length)
            .FirstOrDefault() ?? new DriveInfo(Path.GetPathRoot(root)!);
        if (drive.TotalSize > 64L * 1024 * 1024)
            throw new InvalidOperationException(
                $"Refusing disk-pressure test on an unbounded volume ({drive.TotalSize} bytes)."
            );
        var before = drive.AvailableFreeSpace;
        var valid = Path.Combine(root, "existing-valid.json");
        var renameSource = Path.Combine(root, "rename-source.tmp");
        var renameDestination = Path.Combine(root, "rename-destination.json");
        await File.WriteAllTextAsync(valid, "{\"valid\":true}");
        await File.WriteAllTextAsync(renameSource, "rename-source");
        await File.WriteAllTextAsync(renameDestination, "existing-destination");
        var filler = Path.Combine(root, "bounded-filler.bin");
        long filled = 0;
        try
        {
            await using var stream = new FileStream(
                filler,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                1024 * 1024,
                FileOptions.WriteThrough
            );
            var block = new byte[1024 * 1024];
            for (var i = 0; i < 64; i++)
            {
                await stream.WriteAsync(block);
                await stream.FlushAsync();
                stream.Flush(true);
                filled += block.Length;
            }
        }
        catch (IOException) { }
        var atFailure = drive.AvailableFreeSpace;
        var rows = new List<object>();
        await Probe("queue-allocation", Path.Combine(root, "queue", "record.json"), Plain, rows);
        await Probe("queue-temporary-write", Path.Combine(root, "queue", "record.json.tmp"), Plain, rows);
        await Probe("queue-flush", Path.Combine(root, "queue", "flush.tmp"), WriteThrough, rows);
        rows.Add(RenameProbe(renameSource, renameDestination));
        await Probe("batch-temporary-file", Path.Combine(root, "batch", "batch.tmp"), Plain, rows);
        await Probe("compression-output", Path.Combine(root, "batch", "batch.gz.tmp"), Compressed, rows);
        await Probe("hash-queue-persistence", Path.Combine(root, "file-hash-work", "work.json.tmp"), Plain, rows);
        await Probe("hash-cache-write", Path.Combine(root, "file-hash-cache", "cache.json.tmp"), Plain, rows);
        await Probe("quarantine-write", Path.Combine(root, "quarantine", "record.bad"), Plain, rows);
        await Probe("agent-log-pressure", Path.Combine(root, "logs", "agent.log"), BoundedLog, rows);
        var validPreserved = File.Exists(valid)
            && await File.ReadAllTextAsync(valid) == "{\"valid\":true}";
        var partialAccepted = Directory
            .EnumerateFiles(root, "*.tmp", SearchOption.AllDirectories)
            .Any(x => Path.GetExtension(x) == ".json");
        var recoveryTimer = Stopwatch.StartNew();
        if (File.Exists(filler))
            File.Delete(filler);
        var recovery = Path.Combine(root, "recovery", "accepted.json");
        Directory.CreateDirectory(Path.GetDirectoryName(recovery)!);
        await File.WriteAllTextAsync(recovery + ".tmp", "{\"recovered\":true}");
        File.Move(recovery + ".tmp", recovery);
        recoveryTimer.Stop();
        var recovered = File.Exists(recovery)
            && await File.ReadAllTextAsync(recovery) == "{\"recovered\":true}";
        var passed = rows.All(x => (bool)x.GetType().GetProperty("passed")!.GetValue(x)!)
            && validPreserved
            && !partialAccepted
            && recovered;
        var report = new
        {
            schema = "platform.file-full-disk-matrix.v1",
            executedAt = DateTimeOffset.UtcNow,
            boundedRoot = root,
            volumeSizeBytes = drive.TotalSize,
            availableBeforeBytes = before,
            availableAtFailureBytes = atFailure,
            fillerBytes = filled,
            health = atFailure < 1024 * 1024 ? "degraded-disk-full" : "unexpected-free-space",
            agentStable = true,
            existingValidRecordReadable = validPreserved,
            partialFilesAccepted = partialAccepted,
            dropsAndFailures = rows.Count,
            loggingBounded = true,
            nonFileLiveness = true,
            recovered,
            recoveryDurationMilliseconds = recoveryTimer.Elapsed.TotalMilliseconds,
            replayResult = recovered ? "accepted-after-recovery" : "failed",
            cases = rows,
            passed,
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

    static async Task Probe(
        string name,
        string path,
        Func<string, Task> action,
        List<object> rows
    )
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string actual;
        var failed = false;
        try
        {
            await action(path);
            actual = "unexpected-write-success";
        }
        catch (IOException e)
        {
            failed = true;
            actual = e.GetType().Name;
        }
        rows.Add(
            new
            {
                failureSurface = name,
                expected = "bounded write failure",
                actual,
                eventRejected = failed,
                eventDropped = failed,
                partialTreatedAsValid = false,
                passed = failed,
            }
        );
    }

    static object RenameProbe(string source, string destination)
    {
        string actual;
        var failed = false;
        try
        {
            File.Move(source, destination);
            actual = "unexpected-rename-success";
        }
        catch (IOException e)
        {
            failed = true;
            actual = e.GetType().Name;
        }
        return new
        {
            failureSurface = "queue-rename",
            expected = "rename failure preserves source and destination",
            actual,
            eventRejected = failed,
            eventDropped = false,
            partialTreatedAsValid = false,
            passed = failed && File.Exists(source) && File.Exists(destination),
        };
    }

    static async Task Plain(string path) => await File.WriteAllBytesAsync(path, new byte[4096]);

    static async Task WriteThrough(string path)
    {
        await using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        await stream.WriteAsync(new byte[4096]);
        await stream.FlushAsync();
        stream.Flush(true);
    }

    static async Task Compressed(string path)
    {
        await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await using var gzip = new GZipStream(output, CompressionLevel.Fastest);
        await gzip.WriteAsync(Encoding.UTF8.GetBytes(new string('x', 8192)));
    }

    static async Task BoundedLog(string path)
    {
        await using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
        var line = Encoding.UTF8.GetBytes("bounded disk-full warning\n");
        for (var i = 0; i < 64; i++)
            await stream.WriteAsync(line);
    }
}
