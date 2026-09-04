using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using OpenSecurityPlatform.Foundation;

sealed class WindowsProcessResponse : IDisposable
{
    const uint QueryLimitedInformation = 0x1000;
    const uint TerminateRight = 0x0001;
    const uint Synchronize = 0x00100000;
    const uint ThreadSuspendResume = 0x0002;
    const uint ThreadQueryLimitedInformation = 0x0800;
    const uint SnapshotThreads = 0x00000004;
    const uint WaitObject0 = 0;
    const uint WaitTimeout = 258;
    const uint Infinite = 0xffffffff;
    const int MaximumThreads = 4096;
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    static readonly JsonSerializerOptions IndentedJson = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    static readonly HashSet<string> CriticalNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Registry", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "svchost", "fontdrvhost", "dwm",
        "Platform.Agent", "Platform.Agent.exe"
    };
    readonly string ledgerPath;
    readonly SemaphoreSlim gate = new(1, 1);

    public WindowsProcessResponse(string dataDirectory)
    {
        Directory.CreateDirectory(dataDirectory);
        ledgerPath = Path.Combine(dataDirectory, "process-response-suspensions.v1.json");
    }

    public static async Task<int> RunSelfTestAsync(string dataDirectory, string? fixtureExecutable, string? output)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(fixtureExecutable) || !File.Exists(fixtureExecutable)) return 2;
        var root = Path.Combine(Path.GetFullPath(dataDirectory), "process-response-self-test"); Directory.CreateDirectory(root);
        var heartbeat = Path.Combine(root, "heartbeat.txt"); var treeManifest = Path.Combine(root, "tree.jsonl");
        File.Delete(heartbeat); File.Delete(treeManifest);
        using var executor = new WindowsProcessResponse(root);
        var survivors = new List<(Process Process, ProcessResponseTarget Target)>();
        try
        {
            (Process Process, ProcessResponseTarget Target) Start(string arguments)
            {
                var process = System.Diagnostics.Process.Start(new ProcessStartInfo(fixtureExecutable, arguments) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true }) ?? throw new InvalidOperationException("Controlled fixture did not start.");
                var started = new DateTimeOffset(process.StartTime.ToUniversalTime());
                string? path; try { path = process.MainModule?.FileName; } catch { path = fixtureExecutable; }
                return (process, new ProcessResponseTarget(ProcessIdentity.Create(Guid.Empty, process.Id, started, $"sprint19:{started.UtcTicks}"), process.Id, started, path, null));
            }
            static JsonElement P(string reason, ProcessResponseTarget target) => ProcessResponseSafety.Parameters(reason, target);
            static string State(ProcessExecution result) => result.Structured.GetProperty("state").GetString()!;

            var unrelated = Start("--child --lifetime-ms 60000"); survivors.Add(unrelated);
            var terminate = Start("--child --lifetime-ms 60000");
            var terminateResult = await executor.ExecuteAsync("process.terminate", P("profile A exact terminate", terminate.Target), default);
            await Task.Delay(200); terminate.Process.Refresh(); unrelated.Process.Refresh();
            var profileA = State(terminateResult) == "Terminated" && terminate.Process.HasExited && !unrelated.Process.HasExited;

            var replacement = Start("--child --lifetime-ms 60000"); survivors.Add(replacement);
            var forged = replacement.Target with { ProcessEntityId = new string('f', 64), ProcessStartTime = replacement.Target.ProcessStartTime.AddSeconds(-30) };
            var mismatch = await executor.ExecuteAsync("process.terminate", P("profile B simulated PID reuse", forged), default);
            replacement.Process.Refresh(); var profileB = State(mismatch) == "IdentityMismatch" && !replacement.Process.HasExited;

            var suspended = Start($"--child --lifetime-ms 60000 --heartbeat \"{heartbeat}\""); survivors.Add(suspended);
            await Task.Delay(500); var beforeSuspend = new FileInfo(heartbeat).Length;
            var suspend = await executor.ExecuteAsync("process.suspend", P("profile C suspend", suspended.Target), default);
            await Task.Delay(600); var whileSuspended = new FileInfo(heartbeat).Length;
            var resume = await executor.ExecuteAsync("process.resume", P("profile C resume", suspended.Target), default);
            await Task.Delay(600); var afterResume = new FileInfo(heartbeat).Length;
            var profileC = State(suspend) is "Suspended" or "Partial" && State(resume) is "Running" or "Partial" && whileSuspended - beforeSuspend < 80 && afterResume > whileSuspended;

            var treeRoot = Start($"--tree-node --depth 3 --manifest \"{treeManifest}\" --lifetime-ms 60000");
            var deadline = DateTimeOffset.UtcNow.AddSeconds(10);
            while ((!File.Exists(treeManifest) || File.ReadAllLines(treeManifest).Length < 4) && DateTimeOffset.UtcNow < deadline) await Task.Delay(100);
            var nodes = File.ReadAllLines(treeManifest).Select(line => JsonDocument.Parse(line).RootElement.Clone()).ToArray();
            var targets = nodes.Select(x =>
            {
                var pid = x.GetProperty("pid").GetInt32(); var start = x.GetProperty("startTime").GetDateTimeOffset(); var remaining = x.GetProperty("depth").GetInt32();
                return new ProcessResponseTarget(ProcessIdentity.Create(Guid.Empty, pid, start, $"sprint19-tree:{start.UtcTicks}"), pid, start, x.GetProperty("imagePath").GetString(), null, 3 - remaining);
            }).OrderBy(x => x.Depth).ToArray();
            var preview = new ProcessResponsePreview(ProcessResponseSafety.SchemaVersion, Guid.Empty, "self-test", "process_tree.terminate", DateTimeOffset.UtcNow, new string('e', 64), targets[0], targets, [], 3, null, null, null, null, null, 0, 0, "deepest-first");
            var tree = await executor.ExecuteAsync("process_tree.terminate", ProcessResponseSafety.TreeParameters("profile D pinned tree", preview, 4, 16), default);
            await Task.Delay(300); var profileD = targets.Length == 4 && State(tree) == "Terminated" && targets.All(x => { try { return System.Diagnostics.Process.GetProcessById(x.ProcessId).HasExited; } catch (ArgumentException) { return true; } });

            var selfStart = new DateTimeOffset(System.Diagnostics.Process.GetCurrentProcess().StartTime.ToUniversalTime());
            var self = new ProcessResponseTarget(ProcessIdentity.Create(Guid.Empty, Environment.ProcessId, selfStart), Environment.ProcessId, selfStart, Environment.ProcessPath, null);
            var protectedResult = await executor.ExecuteAsync("process.terminate", P("profile E self protection", self), default);
            var exited = Start("--child --lifetime-ms 100"); await exited.Process.WaitForExitAsync();
            var exitedResult = await executor.ExecuteAsync("process.terminate", P("profile E already exited", exited.Target), default);
            var profileE = State(protectedResult) == "AccessDenied" && State(exitedResult) is "ExitedBeforeAction" or "IdentityMismatch" or "AccessDenied";

            var report = new
            {
                schemaVersion = "process-response-native-self-test.v1",
                platform = Environment.OSVersion.ToString(),
                architecture = RuntimeInformation.OSArchitecture.ToString(),
                elevated = IsElevatedSelfTest(),
                documentedApis = new[] { "OpenProcess", "GetProcessTimes", "QueryFullProcessImageName", "TerminateProcess", "WaitForSingleObject", "CreateToolhelp32Snapshot", "SuspendThread", "ResumeThread", "IsProcessCritical" },
                noShellKill = true,
                profileA = new { result = profileA ? "PASS" : "FAIL", exactTargetExited = terminate.Process.HasExited, unrelatedSurvived = !unrelated.Process.HasExited },
                profileB = new { result = profileB ? "PASS" : "FAIL", state = State(mismatch), replacementSurvived = !replacement.Process.HasExited },
                profileC = new { result = profileC ? "PASS" : "FAIL", suspendState = State(suspend), resumeState = State(resume), beforeSuspend, whileSuspended, afterResume },
                profileD = new { result = profileD ? "PASS" : "FAIL", targets = targets.Length, order = "deepest-first; start-time; entity-id; root-last", state = State(tree) },
                profileE = new { result = profileE ? "PASS" : "FAIL", selfProtection = State(protectedResult), alreadyExited = State(exitedResult) },
                result = profileA && profileB && profileC && profileD && profileE ? "PASS" : "FAIL",
                timestamp = DateTimeOffset.UtcNow
            };
            var json = JsonSerializer.Serialize(report, IndentedJson);
            if (!string.IsNullOrWhiteSpace(output)) await File.WriteAllTextAsync(output, json);
            Console.WriteLine(json); return profileA && profileB && profileC && profileD && profileE ? 0 : 1;
        }
        finally
        {
            foreach (var value in survivors) try { if (!value.Process.HasExited) await executor.ExecuteAsync("process.terminate", ProcessResponseSafety.Parameters("self-test cleanup", value.Target), default); } catch { }
            foreach (var value in survivors) value.Process.Dispose();
        }
    }

    [SupportedOSPlatform("windows")]
    static bool IsElevatedSelfTest()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    public async Task<ProcessExecution> ExecuteAsync(string actionType, JsonElement parameters, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        if (actionType == "process_tree.terminate") return await TreeAsync(parameters, ct);
        var target = parameters.GetProperty("target").Deserialize<ProcessResponseTarget>(Json)!;
        var result = actionType switch
        {
            "process.terminate" => await TerminateAsync(target, ct),
            "process.suspend" => await SuspendAsync(target, ct),
            "process.resume" => await ResumeAsync(target, ct),
            "process.response_status" => Status(target),
            _ => throw new InvalidOperationException("Unsupported structured process response action.")
        };
        return new(result.State is ProcessResponseState.Running or ProcessResponseState.Suspended or ProcessResponseState.Terminated
            ? ResponseActionState.Succeeded : ResponseActionState.Failed,
            JsonSerializer.SerializeToElement(new { schemaVersion = ProcessResponseSafety.SchemaVersion, actionType, state = result.State.ToString(), results = new[] { result } }, Json),
            1, result.State is ProcessResponseState.AccessDenied ? ResponseFailureCategory.Authorization :
                result.State is ProcessResponseState.IdentityMismatch ? ResponseFailureCategory.Integrity :
                result.State is ProcessResponseState.Failed or ProcessResponseState.Unknown ? ResponseFailureCategory.Execution : ResponseFailureCategory.None,
            result.State is ProcessResponseState.Running or ProcessResponseState.Suspended or ProcessResponseState.Terminated ? null : result.Reason);
    }

    static async Task<ProcessExecution> TreeAsync(JsonElement parameters, CancellationToken ct)
    {
        var targets = parameters.GetProperty("targets").Deserialize<ProcessResponseTarget[]>(Json)!;
        var ordered = targets.OrderByDescending(x => x.Depth).ThenBy(x => x.ProcessStartTime).ThenBy(x => x.ProcessEntityId, StringComparer.Ordinal).ToArray();
        var results = new List<ProcessNodeResult>(ordered.Length);
        foreach (var target in ordered)
        {
            ct.ThrowIfCancellationRequested();
            var result = await TerminateAsync(target, ct);
            results.Add(result);
        }
        var succeeded = results.Count(x => x.State is ProcessResponseState.Terminated or ProcessResponseState.ExitedBeforeAction);
        var overall = succeeded == results.Count ? ProcessResponseState.Terminated : succeeded > 0 ? ProcessResponseState.Partial : ProcessResponseState.Failed;
        return new(overall == ProcessResponseState.Terminated ? ResponseActionState.Succeeded : ResponseActionState.Failed,
            JsonSerializer.SerializeToElement(new
            {
                schemaVersion = ProcessResponseSafety.SchemaVersion,
                actionType = "process_tree.terminate",
                state = overall.ToString(),
                graphSnapshotVersion = parameters.GetProperty("graphSnapshotVersion").GetString(),
                capturedAt = parameters.GetProperty("capturedAt").GetDateTimeOffset(),
                dynamicExpansion = false,
                plannedOrder = "deepest-first; start-time; entity-id; root-last",
                results
            }, Json), results.Count,
            overall == ProcessResponseState.Terminated ? ResponseFailureCategory.None : ResponseFailureCategory.Execution,
            overall == ProcessResponseState.Partial ? "The pinned process tree completed partially; exact per-node results are preserved." : overall == ProcessResponseState.Failed ? "No pinned tree target could be terminated." : null);
    }

    static async Task<ProcessNodeResult> TerminateAsync(ProcessResponseTarget target, CancellationToken ct)
    {
        var opened = OpenVerified(target, TerminateRight | QueryLimitedInformation | Synchronize);
        if (opened.Result is { } failure) return failure;
        using var handle = opened.Handle!;
        var pre = "Running";
        if (!TerminateProcess(handle, 0xE0190001)) return Failure(target, Marshal.GetLastWin32Error(), true, pre);
        var wait = await Task.Run(() => WaitForSingleObject(handle, 10000), ct);
        if (wait != WaitObject0) return Result(target, ProcessResponseState.Failed, true, false, pre, "Termination was requested but native exit verification did not complete.", Marshal.GetLastWin32Error());
        return Result(target, ProcessResponseState.Terminated, true, true, pre, "Native process handle became signaled after TerminateProcess.");
    }

    async Task<ProcessNodeResult> SuspendAsync(ProcessResponseTarget target, CancellationToken ct)
    {
        var opened = OpenVerified(target, QueryLimitedInformation);
        if (opened.Result is { } failure) return failure;
        opened.Handle!.Dispose();
        var threads = EnumerateThreads(target.ProcessId);
        if (threads.Length == 0) return Result(target, ProcessResponseState.Failed, true, false, "Running", "No target threads were observable for bounded suspension.");
        var owned = new List<int>(threads.Length); var failures = new List<string>();
        foreach (var tid in threads)
        {
            ct.ThrowIfCancellationRequested();
            using var thread = OpenThread(ThreadSuspendResume | ThreadQueryLimitedInformation, false, (uint)tid);
            if (thread.IsInvalid) { failures.Add($"thread:{tid}:open:{Marshal.GetLastWin32Error()}"); continue; }
            var previous = SuspendThread(thread);
            if (previous == uint.MaxValue) failures.Add($"thread:{tid}:suspend:{Marshal.GetLastWin32Error()}"); else owned.Add(tid);
        }
        if (owned.Count > 0) await SaveOwnedAsync(target, owned.ToArray(), ct);
        var state = owned.Count == threads.Length ? ProcessResponseState.Suspended : owned.Count > 0 ? ProcessResponseState.Partial : ProcessResponseState.Failed;
        return Result(target, state, true, owned.Count > 0, "Running", state == ProcessResponseState.Suspended ? "One response-owned suspend increment applied to every observed thread." : string.Join(';', failures.Take(16)), null, threads.Length, owned.Count);
    }

    async Task<ProcessNodeResult> ResumeAsync(ProcessResponseTarget target, CancellationToken ct)
    {
        var opened = OpenVerified(target, QueryLimitedInformation);
        if (opened.Result is { } failure) return failure;
        opened.Handle!.Dispose();
        var owned = await TakeOwnedAsync(target, ct);
        if (owned is null) return Result(target, ProcessResponseState.Failed, true, false, "Unknown", "No response-owned suspension ledger exists; blind over-resume was refused.");
        var resumed = 0; var failures = new List<string>();
        foreach (var tid in owned.ThreadIds)
        {
            ct.ThrowIfCancellationRequested();
            using var thread = OpenThread(ThreadSuspendResume | ThreadQueryLimitedInformation, false, (uint)tid);
            if (thread.IsInvalid) { failures.Add($"thread:{tid}:exited-or-open:{Marshal.GetLastWin32Error()}"); continue; }
            var previous = ResumeThread(thread);
            if (previous == uint.MaxValue) failures.Add($"thread:{tid}:resume:{Marshal.GetLastWin32Error()}"); else resumed++;
        }
        var state = failures.Count == 0 ? ProcessResponseState.Running : resumed > 0 ? ProcessResponseState.Partial : ProcessResponseState.Failed;
        return Result(target, state, true, resumed > 0, "Suspended", state == ProcessResponseState.Running ? "Exactly one response-owned suspend increment was removed from each recorded thread." : string.Join(';', failures.Take(16)), null, owned.ThreadIds.Length, resumed);
    }

    static ProcessNodeResult Status(ProcessResponseTarget target)
    {
        var opened = OpenVerified(target, QueryLimitedInformation);
        if (opened.Result is { } failure) return failure;
        opened.Handle!.Dispose();
        return Result(target, ProcessResponseState.Running, true, false, "Running", "Stable identity revalidated; Windows does not expose a reliable whole-process suspended-state query through this source.");
    }

    static (SafeProcessHandle? Handle, ProcessNodeResult? Result) OpenVerified(ProcessResponseTarget target, uint rights)
    {
        if (target.ProcessId <= 4 || target.ProcessId == Environment.ProcessId) return (null, Result(target, ProcessResponseState.AccessDenied, false, false, "Unknown", "Critical/system or platform-agent self-target was rejected."));
        var handle = OpenProcess(rights, false, (uint)target.ProcessId);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error(); handle.Dispose();
            return error == 87 ? (null, Result(target, ProcessResponseState.ExitedBeforeAction, false, false, "Exited", "The exact target exited before execution.", error))
                : (null, Failure(target, error, false, "Unknown"));
        }
        if (!GetProcessTimes(handle, out var creation, out _, out _, out _)) { var error = Marshal.GetLastWin32Error(); handle.Dispose(); return (null, Failure(target, error, false, "Unknown")); }
        var liveStart = DateTimeOffset.FromFileTime(creation.ToLong());
        if ((liveStart - target.ProcessStartTime).Duration() > TimeSpan.FromMilliseconds(10))
        {
            handle.Dispose(); return (null, Result(target, ProcessResponseState.IdentityMismatch, false, false, "Running", "PID reuse or target substitution detected from native creation time."));
        }
        var path = QueryPath(handle);
        if (!string.IsNullOrWhiteSpace(target.ImagePath) && !string.IsNullOrWhiteSpace(path) &&
            (Path.IsPathFullyQualified(target.ImagePath)
                ? !Path.GetFullPath(path).Equals(Path.GetFullPath(target.ImagePath), StringComparison.OrdinalIgnoreCase)
                : !Path.GetFileName(path).Equals(Path.GetFileName(target.ImagePath), StringComparison.OrdinalIgnoreCase)))
        {
            handle.Dispose(); return (null, Result(target, ProcessResponseState.IdentityMismatch, false, false, "Running", "The live executable path differs from the pinned target."));
        }
        var name = path is null ? null : Path.GetFileNameWithoutExtension(path);
        if ((name is not null && CriticalNames.Contains(name)) || (path?.Contains("Platform.Agent", StringComparison.OrdinalIgnoreCase) ?? false) || IsProcessCritical(handle, out var critical) && critical)
        {
            handle.Dispose(); return (null, Result(target, ProcessResponseState.AccessDenied, true, false, "Running", "Protected, critical, agent, or management-channel process was rejected."));
        }
        return (handle, null);
    }

    static string? QueryPath(SafeProcessHandle handle)
    {
        var capacity = 32768; var buffer = new char[capacity];
        return QueryFullProcessImageName(handle, 0, buffer, ref capacity) ? new string(buffer, 0, capacity) : null;
    }
    static int[] EnumerateThreads(int pid)
    {
        using var snapshot = CreateToolhelp32Snapshot(SnapshotThreads, 0);
        if (snapshot.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        var entry = new ThreadEntry32 { Size = (uint)Marshal.SizeOf<ThreadEntry32>() }; var values = new List<int>();
        if (Thread32First(snapshot, ref entry)) do { if (entry.OwnerProcessId == (uint)pid) values.Add((int)entry.ThreadId); } while (values.Count < MaximumThreads && Thread32Next(snapshot, ref entry));
        return values.Order().ToArray();
    }

    async Task SaveOwnedAsync(ProcessResponseTarget target, int[] threads, CancellationToken ct)
    {
        await gate.WaitAsync(ct); try { var ledger = await LoadAsync(ct); ledger[target.ProcessEntityId] = new(target.ProcessId, target.ProcessStartTime, threads, DateTimeOffset.UtcNow); await AtomicSaveAsync(ledger, ct); } finally { gate.Release(); }
    }
    async Task<SuspensionLedgerEntry?> TakeOwnedAsync(ProcessResponseTarget target, CancellationToken ct)
    {
        await gate.WaitAsync(ct); try { var ledger = await LoadAsync(ct); if (!ledger.Remove(target.ProcessEntityId, out var value) || value.ProcessId != target.ProcessId || value.ProcessStartTime != target.ProcessStartTime) return null; await AtomicSaveAsync(ledger, ct); return value; } finally { gate.Release(); }
    }
    async Task<Dictionary<string, SuspensionLedgerEntry>> LoadAsync(CancellationToken ct)
    {
        if (!File.Exists(ledgerPath)) return new(StringComparer.Ordinal);
        await using var stream = new FileStream(ledgerPath, FileMode.Open, FileAccess.Read, FileShare.Read, 16384, true);
        return await JsonSerializer.DeserializeAsync<Dictionary<string, SuspensionLedgerEntry>>(stream, Json, ct) ?? new(StringComparer.Ordinal);
    }
    async Task AtomicSaveAsync(Dictionary<string, SuspensionLedgerEntry> value, CancellationToken ct)
    {
        var temp = ledgerPath + ".new"; await using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 16384, true)) { await JsonSerializer.SerializeAsync(stream, value, Json, ct); await stream.FlushAsync(ct); }
        File.Move(temp, ledgerPath, true);
    }

    public void Dispose() { gate.Dispose(); GC.SuppressFinalize(this); }

    static ProcessNodeResult Failure(ProcessResponseTarget target, int error, bool verified, string pre) => Result(target,
        error == 5 ? ProcessResponseState.AccessDenied : error == 87 ? ProcessResponseState.ExitedBeforeAction : ProcessResponseState.Failed,
        verified, false, pre, new Win32Exception(error).Message, error);
    static ProcessNodeResult Result(ProcessResponseTarget target, ProcessResponseState state, bool verified, bool attempted, string pre, string reason, int? nativeError = null, int observedThreads = 0, int affectedThreads = 0) =>
        new(target.ProcessEntityId, target.ProcessId, target.ProcessStartTime, target.ImagePath, target.Depth, true, verified, attempted,
            state is ProcessResponseState.Terminated or ProcessResponseState.Running or ProcessResponseState.Suspended,
            state == ProcessResponseState.ExitedBeforeAction, false, state, pre, state.ToString(), reason, nativeError, observedThreads, affectedThreads, DateTimeOffset.UtcNow);

    public sealed record ProcessExecution(ResponseActionState State, JsonElement Structured, int Records, ResponseFailureCategory Failure, string? FailureReason);
    public sealed record ProcessNodeResult(string ProcessEntityId, int ProcessId, DateTimeOffset ProcessStartTime, string? ImagePath, int Depth,
        bool Requested, bool IdentityVerified, bool Attempted, bool Succeeded, bool AlreadyExited, bool Skipped,
        ProcessResponseState State, string PreState, string PostState, string Reason, int? NativeError, int ObservedThreads, int AffectedThreads, DateTimeOffset CompletedAt);
    sealed record SuspensionLedgerEntry(int ProcessId, DateTimeOffset ProcessStartTime, int[] ThreadIds, DateTimeOffset SuspendedAt);

    [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; public long ToLong() => unchecked((long)(((ulong)High << 32) | Low)); }
    [StructLayout(LayoutKind.Sequential)] struct ThreadEntry32 { public uint Size, Usage, ThreadId, OwnerProcessId; public int BasePriority, DeltaPriority; public uint Flags; }
    sealed class SafeSnapshotHandle : SafeHandleZeroOrMinusOneIsInvalid { SafeSnapshotHandle() : base(true) { } protected override bool ReleaseHandle() => CloseHandle(handle); }
    [DllImport("kernel32.dll", SetLastError = true)] static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessTimes(SafeProcessHandle process, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, [Out] char[] path, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool IsProcessCritical(SafeProcessHandle process, out bool critical);
    [DllImport("kernel32.dll", SetLastError = true)] static extern SafeWaitHandle OpenThread(uint access, bool inherit, uint threadId);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint SuspendThread(SafeWaitHandle thread);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(SafeWaitHandle thread);
    [DllImport("kernel32.dll", SetLastError = true)] static extern SafeSnapshotHandle CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool Thread32First(SafeSnapshotHandle snapshot, ref ThreadEntry32 entry);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool Thread32Next(SafeSnapshotHandle snapshot, ref ThreadEntry32 entry);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
}
