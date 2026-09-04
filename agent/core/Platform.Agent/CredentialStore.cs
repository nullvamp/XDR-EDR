using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
#pragma warning disable CA1416

interface IAgentCredentialStore
{
    Task<AgentState?> LoadAsync(CancellationToken cancellationToken);
    Task SaveAsync(AgentState state, CancellationToken cancellationToken);
}

static class AgentCredentialStore
{
    public static IAgentCredentialStore Create(AgentOptions options)
    {
        if (options.CredentialStore == "development")
        {
            if (options.Environment == "production")
                throw new InvalidOperationException(
                    "The plaintext development credential store is forbidden in production."
                );
            return new FileCredentialStore(options.DataDirectory, false);
        }
        if (OperatingSystem.IsWindows())
            return new FileCredentialStore(options.DataDirectory, true);
        if (OperatingSystem.IsMacOS())
            return new MacKeychainCredentialStore();
        return new FileCredentialStore(options.DataDirectory, false, true);
    }
}

sealed class FileCredentialStore(string directory, bool dpapi, bool enforceUnix = false)
    : IAgentCredentialStore,
        IDisposable
{
    private readonly string _path = Path.Combine(directory, "state.dat");
    private readonly SemaphoreSlim _saveGate = new(1, 1);
    private static readonly byte[] Entropy = SHA256.HashData(
        Encoding.UTF8.GetBytes("open-security-platform-agent-state-v1")
    );

    public async Task<AgentState?> LoadAsync(CancellationToken ct)
    {
        await _saveGate.WaitAsync(ct);
        try
        {
            if (!File.Exists(_path))
                await RecoverInterruptedReplaceAsync(ct);
            if (!File.Exists(_path))
                return null;
            if (
                enforceUnix
                && File.GetUnixFileMode(_path)
                    != (UnixFileMode.UserRead | UnixFileMode.UserWrite)
            )
                throw new InvalidOperationException(
                    "Agent credential file permissions must be 0600."
                );
            var bytes = await File.ReadAllBytesAsync(_path, ct);
            if (dpapi)
                bytes = ProtectedData.Unprotect(bytes, Entropy, DataProtectionScope.LocalMachine);
            return JsonSerializer.Deserialize<AgentState>(bytes)
                ?? throw new InvalidDataException("Agent credential state is invalid.");
        }
        finally
        {
            _saveGate.Release();
        }
    }

    private async Task RecoverInterruptedReplaceAsync(CancellationToken ct)
    {
        if (!Directory.Exists(directory))
            return;
        var candidates = Directory.EnumerateFiles(directory, "state.dat.*.tmp")
            .Concat(Directory.EnumerateFiles(directory, "state.dat~*.TMP"))
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .ToArray();
        foreach (var candidate in candidates)
        {
            try
            {
                var bytes = await File.ReadAllBytesAsync(candidate, ct);
                if (dpapi)
                    bytes = ProtectedData.Unprotect(bytes, Entropy, DataProtectionScope.LocalMachine);
                if (JsonSerializer.Deserialize<AgentState>(bytes) is null)
                    continue;
                File.Move(candidate, _path, true);
                if (enforceUnix)
                    File.SetUnixFileMode(_path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                return;
            }
            catch (Exception error) when (error is CryptographicException or JsonException or IOException)
            {
                // Try the next bounded candidate; invalid remnants remain available for diagnosis.
            }
        }
    }

    public async Task SaveAsync(AgentState state, CancellationToken ct)
    {
        await _saveGate.WaitAsync(ct);
        try
        {
            Directory.CreateDirectory(directory);
            if (enforceUnix)
                File.SetUnixFileMode(
                    directory,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                );
            var bytes = JsonSerializer.SerializeToUtf8Bytes(state);
            if (dpapi)
                bytes = ProtectedData.Protect(bytes, Entropy, DataProtectionScope.LocalMachine);
            var temp = $"{_path}.{Guid.NewGuid():N}.tmp";
            try
            {
                await File.WriteAllBytesAsync(temp, bytes, ct);
                if (enforceUnix)
                    File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                await ReplaceAsync(temp, ct);
            }
            finally
            {
                File.Delete(temp);
            }
            if (
                enforceUnix
                && File.GetUnixFileMode(_path) != (UnixFileMode.UserRead | UnixFileMode.UserWrite)
            )
                throw new InvalidOperationException(
                    "Agent credential file permissions could not be secured."
                );
        }
        finally
        {
            _saveGate.Release();
        }
    }

    public void Dispose() => _saveGate.Dispose();

    private async Task ReplaceAsync(string temp, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                if (OperatingSystem.IsWindows() && File.Exists(_path))
                    File.Replace(temp, _path, null);
                else
                    File.Move(temp, _path, true);
                return;
            }
            catch (Exception error)
                when (OperatingSystem.IsWindows()
                    && attempt < 7
                    && error is IOException or UnauthorizedAccessException)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(25 * (attempt + 1)), ct);
            }
        }
    }
}

sealed class MacKeychainCredentialStore : IAgentCredentialStore
{
    const string Service = "open-security-platform-agent";
    const string Account = "machine-agent";

    public async Task<AgentState?> LoadAsync(CancellationToken ct)
    {
        var result = await Run(
            ["find-generic-password", "-a", Account, "-s", Service, "-w"],
            true,
            ct
        );
        return result.ExitCode == 44 ? null
            : result.ExitCode == 0
                ? JsonSerializer.Deserialize<AgentState>(
                    Convert.FromBase64String(result.Output.Trim())
                )
            : throw new InvalidOperationException("macOS Keychain lookup failed.");
    }

    public async Task SaveAsync(AgentState state, CancellationToken ct)
    {
        var encoded = Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(state));
        var result = await Run(
            ["add-generic-password", "-a", Account, "-s", Service, "-w", encoded, "-U"],
            false,
            ct
        );
        if (result.ExitCode != 0)
            throw new InvalidOperationException("macOS Keychain update failed.");
    }

    private static async Task<(int ExitCode, string Output)> Run(
        string[] args,
        bool capture,
        CancellationToken ct
    )
    {
        var start = new ProcessStartInfo("/usr/bin/security")
        {
            RedirectStandardOutput = capture,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var arg in args)
            start.ArgumentList.Add(arg);
        using var process =
            Process.Start(start)
            ?? throw new InvalidOperationException("macOS Keychain utility is unavailable.");
        var output = capture ? await process.StandardOutput.ReadToEndAsync(ct) : "";
        await process.WaitForExitAsync(ct);
        return (process.ExitCode, output);
    }
}
