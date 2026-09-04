using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Json;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenSecurityPlatform.Foundation;

sealed partial class EndpointLiveResponseWorker(AgentOptions options, IAgentCredentialStore credentials, ILogger<EndpointLiveResponseWorker> log) : BackgroundService
{
    const int Capacity = 16; readonly Channel<(AgentState, SignedLiveCommandEnvelope)> _queue = Channel.CreateBounded<(AgentState, SignedLiveCommandEnvelope)>(new BoundedChannelOptions(Capacity) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = true }); readonly ConcurrentDictionary<Guid, SessionContext> _sessions = new(); readonly ConcurrentDictionary<Guid, byte> _scheduled = new(); readonly ConcurrentDictionary<Guid, byte> _cancelRequested = new(); readonly ConcurrentDictionary<Guid, CancellationTokenSource> _running = new(); readonly ResponseReplayStore _replay = new(Path.Combine(options.DataDirectory, "live-response-replay.json"));
    public override void Dispose() { _replay.Dispose(); base.Dispose(); }
    protected override async Task ExecuteAsync(CancellationToken ct) { var consumer = Consume(ct); try { while (!ct.IsCancellationRequested) { var state = await credentials.LoadAsync(ct); if (state is null) { await Task.Delay(1000, ct); continue; } try { using var client = Client(state); var assignments = await client.GetFromJsonAsync<ApiEnvelope<SignedLiveSessionEnvelope[]>>("/agent/v1/live-response/sessions", ct); foreach (var assignment in assignments?.Data ?? []) await Connect(client, state, assignment, ct); var commands = await client.GetFromJsonAsync<ApiEnvelope<SignedLiveCommandEnvelope[]>>("/agent/v1/live-response/commands", ct); foreach (var command in commands?.Data ?? []) { if (await _replay.ContainsCompletedAsync(command.CommandId, ct) || !_scheduled.TryAdd(command.CommandId, 0)) continue; await _queue.Writer.WriteAsync((state, command), ct); } var cancellations = await client.GetFromJsonAsync<ApiEnvelope<LiveCancellationInstruction[]>>("/agent/v1/live-response/cancellations", ct); foreach (var cancellation in cancellations?.Data ?? []) await HandleCancellation(client, state, cancellation, ct); } catch (Exception e) when (e is HttpRequestException or TaskCanceledException) { log.LogWarning("Live Response poll deferred: {Reason}", e.Message); } await Task.Delay(250, ct); } } catch (OperationCanceledException) when (ct.IsCancellationRequested) { } finally { _queue.Writer.TryComplete(); await consumer; } }
    async Task Connect(HttpClient client, AgentState state, SignedLiveSessionEnvelope session, CancellationToken ct) { Validate(state, session); if (_sessions.ContainsKey(session.SessionId)) return; var root = AllowedRoots()[0]; var context = new SessionContext(session.SessionId, root, session.Capabilities, session.Nonce); if (!_sessions.TryAdd(session.SessionId, context)) return; using var response = await client.PostAsJsonAsync($"/agent/v1/live-response/sessions/{session.SessionId:D}:transition", new LiveAgentSessionTransition(session.SessionId, state.InstallationId, session.Nonce, LiveSessionState.Active, DateTimeOffset.UtcNow, $"pid:{Environment.ProcessId};user:{Environment.UserName}", Integrity(), root, "signed session connected"), ct); response.EnsureSuccessStatusCode(); }
    async Task Consume(CancellationToken ct) { await foreach (var item in _queue.Reader.ReadAllAsync(ct)) { try { await Execute(item.Item1, item.Item2, ct); } catch (OperationCanceledException) when (ct.IsCancellationRequested) { } catch (Exception e) { log.LogError(e, "Live Response command {CommandId} failed", item.Item2.CommandId); } finally { _scheduled.TryRemove(item.Item2.CommandId, out _); } } }
    async Task Execute(AgentState state, SignedLiveCommandEnvelope command, CancellationToken serviceToken)
    {
        Validate(state, command); if (!_sessions.TryGetValue(command.SessionId, out var session)) throw new InvalidDataException("Live Response session is not connected."); if (!await _replay.TryStartAsync(command.CommandId, command.Nonce, command.InputHash, serviceToken)) return; using var client = Client(state); using var timeout = CancellationTokenSource.CreateLinkedTokenSource(serviceToken); _running[command.CommandId] = timeout; timeout.CancelAfter(TimeSpan.FromSeconds(command.TimeoutSeconds)); try
        {
            if (_cancelRequested.ContainsKey(command.CommandId)) { await Transition(client, command, LiveCommandState.Cancelled, "cancellation acknowledged before execution", serviceToken); await _replay.CompleteAsync(command.CommandId, "cancelled-before-execution", serviceToken); return; }
            await Transition(client, command, LiveCommandState.Acknowledged, "signed command accepted", serviceToken); await Transition(client, command, LiveCommandState.Running, "bounded executor started", serviceToken); var started = DateTimeOffset.UtcNow; var output = new List<(string Stream, string Text)>(); var artifacts = new List<LiveArtifactUpload>(); var sequence = 0; var bytes = 0; var limited = false; using var emitGate = new SemaphoreSlim(1, 1); async Task Emit(string stream, string text) { await emitGate.WaitAsync(serviceToken); try { var clean = Sanitize(text); var available = LiveResponseSafety.HardLimits.MaximumOutputBytes - bytes; if (available <= 0) { limited = true; return; } var encoded = Encoding.UTF8.GetBytes(clean); if (encoded.Length > available) { clean = Encoding.UTF8.GetString(encoded.AsSpan(0, available)); limited = true; } bytes += Encoding.UTF8.GetByteCount(clean); var chunk = new LiveOutputChunk(command.CommandId, sequence++, stream, clean, LiveResponseSafety.Hash(clean), DateTimeOffset.UtcNow, limited, limited); using var response = await client.PostAsJsonAsync($"/agent/v1/live-response/commands/{command.CommandId:D}/chunks", chunk, serviceToken); response.EnsureSuccessStatusCode(); output.Add((stream, clean)); } finally { emitGate.Release(); } }
            Execution execution; try { execution = command.CommandType switch { LiveCommandType.BuiltIn => await BuiltIn(client, session, command, Emit, artifacts, timeout.Token), LiveCommandType.Cmd => await Shell(command, "cmd.exe", Emit, timeout.Token), LiveCommandType.PowerShell => await PowerShell(command, Emit, timeout.Token), LiveCommandType.Upload => await Upload(session, command, Emit, timeout.Token), _ => throw new InvalidOperationException("Unsupported Live Response command type.") }; } catch (OperationCanceledException) when (!serviceToken.IsCancellationRequested && _cancelRequested.ContainsKey(command.CommandId)) { execution = new(LiveCommandState.Cancelled, null, "analyst cancellation", "agent", Integrity()); } catch (OperationCanceledException) when (!serviceToken.IsCancellationRequested) { execution = new(LiveCommandState.TimedOut, null, "command timeout", "agent", Integrity()); } catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or HttpRequestException or CryptographicException) { execution = new(LiveCommandState.Failed, null, e.GetType().Name, "agent", Integrity()); await Emit("stderr", "Command failed safely.\n"); }
            var completed = DateTimeOffset.UtcNow; var hash = LiveResponseSafety.Hash(string.Concat(output.Select(x => $"{x.Stream}:{x.Text}"))); var stdout = output.Where(x => x.Stream == "stdout").Sum(x => Encoding.UTF8.GetByteCount(x.Text)); var stderr = output.Where(x => x.Stream == "stderr").Sum(x => Encoding.UTF8.GetByteCount(x.Text)); var result = new LiveCommandResult(started, completed, execution.State, execution.ExitCode, stdout, stderr, limited, limited, hash, execution.Identity, execution.Integrity, execution.State == LiveCommandState.Succeeded ? null : execution.State.ToString(), execution.Failure, session.WorkingDirectory, []); using var completion = await client.PostAsJsonAsync($"/agent/v1/live-response/commands/{command.CommandId:D}:complete", new LiveAgentCompletion(command.SessionId, command.CommandId, state.InstallationId, command.Nonce, command.InputHash, result, artifacts.ToArray()), serviceToken); completion.EnsureSuccessStatusCode(); await _replay.CompleteAsync(command.CommandId, hash, serviceToken);
        }
        finally { _running.TryRemove(command.CommandId, out _); _cancelRequested.TryRemove(command.CommandId, out _); }
    }
    async Task<Execution> BuiltIn(HttpClient client, SessionContext session, SignedLiveCommandEnvelope command,
        Func<string, string, Task> emit, List<LiveArtifactUpload> artifacts, CancellationToken ct)
    {
        var t = LiveResponseSafety.Tokenize(command.ExactInput); var name = t[0].ToLowerInvariant(); string text;
        switch (name)
        {
            case "help": text = string.Join(' ', LiveResponseSafety.BuiltIns) + "\n"; break;
            case "pwd": text = session.WorkingDirectory + "\n"; break;
            case "cd": session.WorkingDirectory = Resolve(session, t[1], true); text = session.WorkingDirectory + "\n"; break;
            case "ls":
                var dir = t.Length == 2 ? Resolve(session, t[1], true) : session.WorkingDirectory;
                text = JsonSerializer.Serialize(Directory.EnumerateFileSystemEntries(dir).Take(200).Select(x => { var i = new FileInfo(x); return new { name = Path.GetFileName(x), path = x, directory = Directory.Exists(x), size = i.Exists ? i.Length : (long?)null, lastWrite = i.Exists ? i.LastWriteTimeUtc : (DateTime?)null }; })) + "\n"; break;
            case "ps": text = JsonSerializer.Serialize(Process.GetProcesses().OrderBy(x => x.Id).Take(100).Select(x => { try { return new { pid = x.Id, name = x.ProcessName, start = Try(() => x.StartTime.ToUniversalTime()), image = Try(() => x.MainModule?.FileName) }; } finally { x.Dispose(); } })) + "\n"; break;
            case "services": text = OperatingSystem.IsWindows() ? Services() : throw new PlatformNotSupportedException(); break;
            case "connections":
                var ip = IPGlobalProperties.GetIPGlobalProperties(); text = JsonSerializer.Serialize(ip.GetActiveTcpConnections().Take(100).Select(x => new { protocol = "tcp", local = x.LocalEndPoint.ToString(), remote = x.RemoteEndPoint.ToString(), state = x.State.ToString() })) + "\n"; break;
            case "hash":
                var hashPath = Resolve(session, t[1], false); var hashInfo = new FileInfo(hashPath);
                if (!hashInfo.Exists || hashInfo.Length > ArtifactTransferSafety.MaximumArtifactBytes) throw new InvalidOperationException("File is unavailable or exceeds hash policy.");
                var before = Snapshot(hashPath); await using (var stream = new FileStream(hashPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 256 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan)) text = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct)).ToLowerInvariant() + "\n";
                if (before != Snapshot(hashPath)) throw new InvalidOperationException("File changed during hashing."); break;
            case "stat":
                var statPath = Resolve(session, t[1], false); var stat = new FileInfo(statPath); text = JsonSerializer.Serialize(new { path = statPath, exists = stat.Exists, size = stat.Exists ? stat.Length : 0, created = stat.Exists ? stat.CreationTimeUtc : (DateTime?)null, modified = stat.Exists ? stat.LastWriteTimeUtc : (DateTime?)null, nativeIdentity = stat.Exists ? NativeIdentity(statPath) : null }) + "\n"; break;
            case "get":
                var getPath = Resolve(session, t[1], false); var info = new FileInfo(getPath);
                if (!info.Exists || info.Length > ArtifactTransferSafety.MaximumArtifactBytes) throw new InvalidOperationException("File is unavailable or exceeds large-artifact transfer policy.");
                var first = Snapshot(getPath); var artifactId = Guid.NewGuid();
                var uploaded = await ArtifactTransferClient.UploadFileAsync(client, "live-response", command.CommandId,
                    artifactId, getPath, Path.GetFileName(getPath), "application/octet-stream", first.Identity, ct);
                var second = Snapshot(getPath); if (first != second) throw new InvalidOperationException("File changed during acquisition.");
                artifacts.Add(new(artifactId, Path.GetFileName(getPath), "application/octet-stream", uploaded.Sha256,
                    second.Identity, true, null, uploaded.Status.TransferId, info.Length));
                text = JsonSerializer.Serialize(new
                {
                    artifactId,
                    transferId = uploaded.Status.TransferId,
                    path = getPath,
                    size = info.Length,
                    sha256 = uploaded.Sha256,
                    nativeIdentity = second.Identity,
                    consistent = true,
                    resumable = true,
                    chunkSize = uploaded.Status.ChunkSize
                }) + "\n"; break;
            case "stage-tool":
                text = await StageTool(client, Guid.Parse(t[1]), ct); break;
            case "remove-tool":
                text = RemoveTool(Guid.Parse(t[1])); break;
            case "session-info": text = JsonSerializer.Serialize(new { sessionId = session.SessionId, workingDirectory = session.WorkingDirectory, capabilities = session.Capabilities, executionIdentity = $"pid:{Environment.ProcessId};user:{Environment.UserName}", integrity = Integrity(), agentVersion = ProductRelease.Version }) + "\n"; break;
            default: throw new InvalidOperationException("Unsupported built-in.");
        }
        await emit("stdout", text); return new(LiveCommandState.Succeeded, 0, null, $"pid:{Environment.ProcessId};builtin:{name}", Integrity());
    }

    async Task<string> StageTool(HttpClient client, Guid packageId, CancellationToken ct)
    {
        var metadata = await client.GetFromJsonAsync<ApiEnvelope<ApprovedToolPackage>>($"/agent/v1/live-response/tool-packages/{packageId:D}", ct)
            ?? throw new InvalidDataException("Approved tool package metadata is invalid.");
        var package = metadata.Data;
        ToolPackageSafety.Validate(package.Name, package.Version, package.FileName, package.Size, package.Sha256,
            package.ExpectedSignerThumbprint, package.AllowUnsigned);
        var root = Path.Combine(options.DataDirectory, "approved-tools", package.PackageId.ToString("D"));
        Directory.CreateDirectory(root); var path = Path.Combine(root, package.FileName); var temporary = path + ".download";
        try
        {
            using var response = await client.GetAsync($"/agent/v1/live-response/tool-packages/{packageId:D}/content", HttpCompletionOption.ResponseHeadersRead, ct);
            response.EnsureSuccessStatusCode();
            await using (var source = await response.Content.ReadAsStreamAsync(ct))
            await using (var output = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None, 256 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough))
            { await source.CopyToAsync(output, 256 * 1024, ct); await output.FlushAsync(ct); output.Flush(true); }
            var info = new FileInfo(temporary); string hash; await using (var input = File.OpenRead(temporary)) hash = Convert.ToHexString(await SHA256.HashDataAsync(input, ct)).ToLowerInvariant();
            if (info.Length != package.Size || !string.Equals(hash, package.Sha256, StringComparison.OrdinalIgnoreCase)) throw new CryptographicException("Staged tool package hash verification failed.");
            var signer = ToolSigner(temporary);
            if (signer.State == "invalid") throw new CryptographicException("Tool package carries an invalid Authenticode signature.");
            if (package.ExpectedSignerThumbprint is not null && (signer.State != "valid" || !string.Equals(signer.Thumbprint, package.ExpectedSignerThumbprint, StringComparison.OrdinalIgnoreCase))) throw new CryptographicException("Staged tool signer does not match approved package policy.");
            if (package.ExpectedSignerThumbprint is null && (!package.AllowUnsigned || signer.State != "unsigned")) throw new CryptographicException("Tool signer state does not match the approved package policy.");
            File.Move(temporary, path, false);
            return JsonSerializer.Serialize(new
            {
                packageId,
                package.Name,
                package.Version,
                path,
                package.Size,
                sha256 = hash,
                signer = signer.Thumbprint ?? "unsigned-approved",
                signerState = signer.State,
                executed = false,
                cleanupRequired = true
            }) + "\n";
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    string RemoveTool(Guid packageId)
    {
        var root = Path.GetFullPath(Path.Combine(options.DataDirectory, "approved-tools", packageId.ToString("D")));
        var expectedRoot = Path.GetFullPath(Path.Combine(options.DataDirectory, "approved-tools")) + Path.DirectorySeparatorChar;
        if (!root.StartsWith(expectedRoot, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Tool cleanup path is outside the owned staging root.");
        if (Directory.Exists(root)) Directory.Delete(root, true);
        return JsonSerializer.Serialize(new { packageId, removed = !Directory.Exists(root), ownedPathOnly = true }) + "\n";
    }

    static (string State, string? Thumbprint) ToolSigner(string path)
    {
        if (!OperatingSystem.IsWindows()) return ("unsupported", null);
        X509Certificate2 certificate;
        try { certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)); }
        catch (CryptographicException) { return ("unsigned", null); }
        using (certificate) return (VerifyAuthenticode(path) ? "valid" : "invalid", certificate.Thumbprint?.ToLowerInvariant());
    }

    static bool VerifyAuthenticode(string path)
    {
        var file = new WinTrustFileInfo(path); var filePointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(file, filePointer, false);
            var data = new WinTrustData(filePointer); var action = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
            return WinVerifyTrust(new IntPtr(-1), ref action, ref data) == 0;
        }
        finally { Marshal.DestroyStructure<WinTrustFileInfo>(filePointer); Marshal.FreeHGlobal(filePointer); }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    readonly struct WinTrustFileInfo
    {
        public readonly uint Size; [MarshalAs(UnmanagedType.LPWStr)] public readonly string FilePath;
        public readonly IntPtr FileHandle; public readonly IntPtr KnownSubject;
        public WinTrustFileInfo(string path) { Size = (uint)Marshal.SizeOf<WinTrustFileInfo>(); FilePath = path; FileHandle = IntPtr.Zero; KnownSubject = IntPtr.Zero; }
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    readonly struct WinTrustData
    {
        public readonly uint Size; public readonly IntPtr PolicyCallbackData, SipClientData; public readonly uint UiChoice, RevocationChecks, UnionChoice;
        public readonly IntPtr FileInfo; public readonly uint StateAction; public readonly IntPtr StateData, UrlReference; public readonly uint ProviderFlags, UiContext;
        public WinTrustData(IntPtr file) { Size = (uint)Marshal.SizeOf<WinTrustData>(); PolicyCallbackData = SipClientData = IntPtr.Zero; UiChoice = 2; RevocationChecks = 0; UnionChoice = 1; FileInfo = file; StateAction = 0; StateData = UrlReference = IntPtr.Zero; ProviderFlags = 0x1000; UiContext = 0; }
    }
    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref WinTrustData data);
    static async Task<Execution> Shell(SignedLiveCommandEnvelope command, string file, Func<string, string, Task> emit, CancellationToken ct) { if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException(); var psi = new ProcessStartInfo(file) { WorkingDirectory = command.WorkingDirectory, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true }; psi.ArgumentList.Add("/d"); psi.ArgumentList.Add("/s"); psi.ArgumentList.Add("/c"); psi.ArgumentList.Add(command.ExactInput); return await RunProcess(psi, null, emit, "console:noninteractive", ct); }
    async Task<Execution> PowerShell(SignedLiveCommandEnvelope command, Func<string, string, Task> emit, CancellationToken ct) { if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException(); var psi = new ProcessStartInfo("powershell.exe") { WorkingDirectory = command.WorkingDirectory, UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true }; psi.ArgumentList.Add("-NoLogo"); psi.ArgumentList.Add("-NoProfile"); psi.ArgumentList.Add("-NonInteractive"); psi.ArgumentList.Add("-Command"); psi.ArgumentList.Add("-"); psi.Environment["PSModuleAnalysisCachePath"] = Path.Combine(options.DataDirectory, "live-response-psmodule-cache"); return await RunProcess(psi, command.ExactInput, emit, "executionPolicy:inherited;profile:false;interactive:false;history:persisted:false", ct); }
    static async Task<Execution> RunProcess(ProcessStartInfo psi, string? stdin, Func<string, string, Task> emit, string environment, CancellationToken ct) { using var process = new Process { StartInfo = psi }; if (!process.Start()) throw new InvalidOperationException("Command process did not start."); var identity = $"pid:{process.Id};start:{process.StartTime.ToUniversalTime():O};image:{psi.FileName};{environment}"; using var registration = ct.Register(() => { try { if (!process.HasExited) process.Kill(false); } catch (InvalidOperationException) { } }); if (stdin is not null) { await process.StandardInput.WriteAsync(stdin); await process.StandardInput.FlushAsync(ct); process.StandardInput.Close(); } async Task Pump(StreamReader reader, string stream) { var buffer = new char[4096]; int read; while ((read = await reader.ReadAsync(buffer, ct)) > 0) await emit(stream, new string(buffer, 0, read)); } var stdout = Pump(process.StandardOutput, "stdout"); var stderr = Pump(process.StandardError, "stderr"); await process.WaitForExitAsync(ct); await Task.WhenAll(stdout, stderr); return new(process.ExitCode == 0 ? LiveCommandState.Succeeded : LiveCommandState.Failed, process.ExitCode, process.ExitCode == 0 ? null : "non-zero exit code", identity, Integrity()); }
    async Task<Execution> Upload(SessionContext session, SignedLiveCommandEnvelope command, Func<string, string, Task> emit, CancellationToken ct) { if (command.Overwrite || command.UploadContentBase64 is null || command.UploadSha256 is null) throw new InvalidOperationException("Upload policy is invalid."); var path = Resolve(session, command.ExactInput, false); var bytes = Convert.FromBase64String(command.UploadContentBase64); if (bytes.Length > LiveResponseSafety.HardLimits.MaximumTransferBytes || !string.Equals(Convert.ToHexString(SHA256.HashData(bytes)), command.UploadSha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Upload integrity is invalid."); await using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, true)) await stream.WriteAsync(bytes, ct); string verified; await using (var read = File.OpenRead(path)) verified = Convert.ToHexString(await SHA256.HashDataAsync(read, ct)).ToLowerInvariant(); if (!string.Equals(verified, command.UploadSha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Endpoint upload verification failed."); await emit("stdout", JsonSerializer.Serialize(new { path, size = bytes.Length, sha256 = command.UploadSha256, overwrite = false, executed = false }) + "\n"); return new(LiveCommandState.Succeeded, 0, null, $"pid:{Environment.ProcessId};upload", Integrity()); }
    async Task HandleCancellation(HttpClient client, AgentState state, LiveCancellationInstruction x, CancellationToken ct) { if (x.TenantId != state.TenantId || x.EndpointId != state.EndpointId || x.AgentId != state.AgentId || x.AgentInstallationId != state.InstallationId) throw new InvalidDataException("Cancellation binding is invalid."); _cancelRequested[x.CommandId] = 0; if (_running.TryGetValue(x.CommandId, out var running)) { running.Cancel(); return; } if (_scheduled.ContainsKey(x.CommandId)) return; using var response = await client.PostAsJsonAsync($"/agent/v1/live-response/commands/{x.CommandId:D}:transition", new LiveAgentCommandTransition(x.SessionId, x.CommandId, x.AgentInstallationId, x.Nonce, x.InputHash, LiveCommandState.Cancelled, DateTimeOffset.UtcNow, "cancellation acknowledged after reconnect"), ct); response.EnsureSuccessStatusCode(); _cancelRequested.TryRemove(x.CommandId, out _); }
    static async Task Transition(HttpClient client, SignedLiveCommandEnvelope c, LiveCommandState state, string reason, CancellationToken ct) { using var response = await client.PostAsJsonAsync($"/agent/v1/live-response/commands/{c.CommandId:D}:transition", new LiveAgentCommandTransition(c.SessionId, c.CommandId, c.AgentInstallationId, c.Nonce, c.InputHash, state, DateTimeOffset.UtcNow, reason), ct); response.EnsureSuccessStatusCode(); }
    static void Validate(AgentState state, SignedLiveSessionEnvelope s) { if (s.TenantId != state.TenantId || s.EndpointId != state.EndpointId || s.AgentId != state.AgentId || s.AgentInstallationId != state.InstallationId || s.ExpiresAt <= DateTimeOffset.UtcNow || !LiveResponseSafety.Verify(s, state.CaCertificatePem)) throw new CryptographicException("Live Response session integrity or binding is invalid."); LiveResponseSafety.ValidateCapabilities(s.Capabilities); }
    static void Validate(AgentState state, SignedLiveCommandEnvelope c) { if (c.TenantId != state.TenantId || c.EndpointId != state.EndpointId || c.AgentId != state.AgentId || c.AgentInstallationId != state.InstallationId || c.ExpiresAt <= DateTimeOffset.UtcNow || !LiveResponseSafety.Verify(c, state.CaCertificatePem)) throw new CryptographicException("Live Response command integrity or binding is invalid."); LiveResponseSafety.ValidateInput(c.CommandType, c.ExactInput); }
    string Resolve(SessionContext session, string path, bool directory) { if (path.Contains('%', StringComparison.Ordinal)) throw new UnauthorizedAccessException("Environment expansion is disabled."); if (path.StartsWith("\\\\", StringComparison.Ordinal) && Environment.GetEnvironmentVariable("PLATFORM_LIVE_RESPONSE_ALLOW_UNC") != "true") throw new UnauthorizedAccessException("UNC paths are disabled."); var full = Path.GetFullPath(path, session.WorkingDirectory); var allowed = AllowedRoots().Any(root => full.Equals(root, StringComparison.OrdinalIgnoreCase) || full.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)); if (!allowed) throw new UnauthorizedAccessException("Path is outside Live Response policy roots."); var current = directory ? full : Path.GetDirectoryName(full)!; while (!string.IsNullOrEmpty(current) && AllowedRoots().Any(root => current.StartsWith(root, StringComparison.OrdinalIgnoreCase))) { if (File.Exists(current) || Directory.Exists(current)) { var attributes = File.GetAttributes(current); if ((attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Reparse points are disabled by Live Response policy."); } current = Path.GetDirectoryName(current)!; } if (directory && !Directory.Exists(full)) throw new DirectoryNotFoundException(); return full; }
    string[] AllowedRoots() { var configured = Environment.GetEnvironmentVariable("PLATFORM_LIVE_RESPONSE_ROOTS"); var roots = (configured ?? string.Join(Path.PathSeparator, Path.GetFullPath(options.DataDirectory), Path.GetTempPath())).Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(); return roots.Length == 0 ? [Path.GetFullPath(options.DataDirectory)] : roots; }
    static SnapshotValue Snapshot(string path) { var i = new FileInfo(path); i.Refresh(); return new(i.Length, i.LastWriteTimeUtc, NativeIdentity(path) ?? "unavailable"); }
    static T? Try<T>(Func<T> value) { try { return value(); } catch { return default; } }
    static string Sanitize(string value) => LiveResponseSafety.SanitizeOutput(value); static string Integrity() { if (!OperatingSystem.IsWindows()) return Environment.UserName == "root" ? "high" : "standard"; using var identity = System.Security.Principal.WindowsIdentity.GetCurrent(); return new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator) ? "high" : "standard"; }
    [SupportedOSPlatform("windows")] static string Services() { if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException(); using var searcher = new System.Management.ManagementObjectSearcher("SELECT Name,DisplayName,State,StartMode,ProcessId FROM Win32_Service"); return JsonSerializer.Serialize(searcher.Get().Cast<System.Management.ManagementObject>().Take(200).Select(x => new { name = x["Name"]?.ToString(), displayName = x["DisplayName"]?.ToString(), state = x["State"]?.ToString(), startMode = x["StartMode"]?.ToString(), pid = x["ProcessId"]?.ToString() })) + "\n"; }
    static string? NativeIdentity(string path) { if (!OperatingSystem.IsWindows()) return null; try { using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete); if (!GetFileInformationByHandle(handle, out var x)) return null; return $"{x.VolumeSerialNumber.ToString("x8", CultureInfo.InvariantCulture)}:{(((ulong)x.FileIndexHigh << 32) | x.FileIndexLow).ToString("x16", CultureInfo.InvariantCulture)}"; } catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException) { return null; } }
    HttpClient Client(AgentState state) { var handler = new HttpClientHandler(); handler.ClientCertificates.Add(new X509Certificate2(Convert.FromBase64String(state.ClientCertificatePfx), (string?)null, X509KeyStorageFlags.MachineKeySet)); if (options.ControlPlaneUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) { var root = X509Certificate2.CreateFromPem(state.CaCertificatePem); handler.ServerCertificateCustomValidationCallback = (_, certificate, _, _) => { if (certificate is null) return false; using var chain = new X509Chain(); chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust; chain.ChainPolicy.CustomTrustStore.Add(root); chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; return chain.Build(new X509Certificate2(certificate)); }; } var client = new HttpClient(handler) { BaseAddress = new Uri(options.ControlPlaneUrl), Timeout = TimeSpan.FromSeconds(20) }; client.DefaultRequestHeaders.Add("X-Agent-Installation-Id", state.InstallationId); return client; }
    sealed class SessionContext(Guid id, string cwd, string[] capabilities, string nonce) { public Guid SessionId { get; } = id; public string WorkingDirectory { get; set; } = cwd; public string[] Capabilities { get; } = capabilities; public string Nonce { get; } = nonce; }
    sealed record Execution(LiveCommandState State, int? ExitCode, string? Failure, string Identity, string Integrity); sealed record SnapshotValue(long Length, DateTime LastWrite, string Identity);
    [StructLayout(LayoutKind.Sequential)] struct ByHandleFileInformation { public uint FileAttributes; public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, LastAccessTime, LastWriteTime; public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow; }
    [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle handle, out ByHandleFileInformation information);
    [GeneratedRegex("\\x1B(?:[@-Z\\-_]|\\[[0-?]*[ -/]*[@-~])", RegexOptions.CultureInvariant)] private static partial Regex AnsiRegex();
}
