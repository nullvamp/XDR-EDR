using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OpenSecurityPlatform.Foundation;

sealed class WindowsNetworkIsolation(string dataDirectory)
{
    readonly string _statePath = Path.Combine(dataDirectory, "network-isolation-state.json");
    static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public async Task<EndpointIsolationSnapshot> IsolateAsync(AgentState agent, SignedResponseActionEnvelope action, CancellationToken ct)
    {
        EnsureWindowsAdministrator();
        var destinations = Destinations(action.Parameters);
        var group = Group(agent.InstallationId);
        var previous = await LoadAsync(ct);
        if (previous is { EffectiveState: EndpointIsolationState.Isolated } && previous.PolicyVersion == action.PolicyVersion)
            return await StatusAsync(agent, action, ct);

        await RemoveOwnedAsync(group, ct);
        try
        {
            var rules = BuildRules(group, destinations);
            foreach (var rule in rules) await PowerShellAsync(rule, ct);
            var owned = await CountOwnedAsync(group, ct);
            var management = await VerifyManagementAsync(destinations, ct);
            var verified = owned == rules.Count && management;
            if (!verified)
            {
                await RemoveOwnedAsync(group, ct);
                return await SaveAsync(Snapshot(agent, action, EndpointIsolationState.Isolated,
                    management && owned > 0 ? EndpointIsolationState.PartialIsolation : EndpointIsolationState.Failed,
                    destinations, new(owned == rules.Count, management, false, "failed", DateTimeOffset.UtcNow),
                    management ? "Owned isolation controls could not be verified." : "Management channel survival could not be guaranteed; owned controls were rolled back.",
                    IsolationDriftState.MissingOwnedControls, previous?.EffectiveSince), ct);
            }
            return await SaveAsync(Snapshot(agent, action, EndpointIsolationState.Isolated, EndpointIsolationState.Isolated,
                destinations, new(true, true, true, "passed", DateTimeOffset.UtcNow), null,
                IsolationDriftState.None, DateTimeOffset.UtcNow), ct);
        }
        catch
        {
            await RemoveOwnedAsync(group, CancellationToken.None);
            throw;
        }
    }

    public async Task<EndpointIsolationSnapshot> UnisolateAsync(AgentState agent, SignedResponseActionEnvelope action, CancellationToken ct)
    {
        EnsureWindowsAdministrator();
        var prior = await LoadAsync(ct); var destinations = Destinations(action.Parameters); var group = Group(agent.InstallationId);
        await RemoveOwnedAsync(group, ct);
        var remaining = await CountOwnedAsync(group, ct);
        var verification = new IsolationVerification(remaining == 0, true, false, remaining == 0 ? "passed" : "failed", DateTimeOffset.UtcNow);
        return await SaveAsync(Snapshot(agent, action, EndpointIsolationState.NotIsolated,
            remaining == 0 ? EndpointIsolationState.NotIsolated : EndpointIsolationState.Failed,
            destinations, verification, remaining == 0 ? null : "One or more platform-owned controls remained after unisolation.",
            remaining == 0 ? IsolationDriftState.None : IsolationDriftState.UnexpectedOwnedControls, prior?.EffectiveSince), ct);
    }

    public async Task<EndpointIsolationSnapshot> StatusAsync(AgentState agent, SignedResponseActionEnvelope action, CancellationToken ct)
    {
        EnsureWindowsAdministrator();
        var previous = await LoadAsync(ct); var destinations = Destinations(action.Parameters); var group = Group(agent.InstallationId);
        var count = await CountOwnedAsync(group, ct);
        if (previous?.EffectiveState == EndpointIsolationState.Isolated)
        {
            var management = await VerifyManagementAsync(destinations, ct);
            var state = count > 0 && management ? EndpointIsolationState.Isolated : count > 0 ? EndpointIsolationState.PartialIsolation : EndpointIsolationState.Failed;
            return await SaveAsync(Snapshot(agent, action, previous.RequestedState, state, destinations,
                new(count > 0, management, count > 0, count > 0 && management ? "passed" : "failed", DateTimeOffset.UtcNow),
                count == 0 ? "Previously persisted isolation controls are missing." : management ? null : "Management channel verification failed.",
                count == 0 ? IsolationDriftState.MissingOwnedControls : management ? IsolationDriftState.None : IsolationDriftState.VerificationStale,
                previous.EffectiveSince), ct);
        }
        var effective = count == 0 ? EndpointIsolationState.NotIsolated : EndpointIsolationState.PartialIsolation;
        return await SaveAsync(Snapshot(agent, action, previous?.RequestedState ?? EndpointIsolationState.NotIsolated,
            effective, destinations, new(count == 0, true, false, count == 0 ? "passed" : "failed", DateTimeOffset.UtcNow),
            count == 0 ? null : "Platform-owned isolation controls exist without a matching isolated state.",
            count == 0 ? IsolationDriftState.None : IsolationDriftState.UnexpectedOwnedControls, previous?.EffectiveSince), ct);
    }

    static EndpointIsolationSnapshot Snapshot(AgentState agent, SignedResponseActionEnvelope action,
        EndpointIsolationState requested, EndpointIsolationState effective, ManagementDestination[] destinations,
        IsolationVerification verification, string? failure, IsolationDriftState drift, DateTimeOffset? effectiveSince) =>
        new(IsolationSafety.SchemaVersion, agent.TenantId, agent.EndpointId, agent.InstallationId, requested, effective,
            effectiveSince, verification.VerifiedAt, action.PolicyVersion, IsolationSafety.EnforcementMechanism,
            destinations, verification, failure, drift, action.ActionId, null, null,
            action.Parameters.GetProperty("reason").GetString(), null, null, DateTimeOffset.UtcNow);

    async Task<EndpointIsolationSnapshot> SaveAsync(EndpointIsolationSnapshot value, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_statePath)!);
        var temporary = _statePath + ".tmp";
        await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(value, Json), ct);
        File.Move(temporary, _statePath, true);
        return value;
    }

    async Task<EndpointIsolationSnapshot?> LoadAsync(CancellationToken ct)
    {
        if (!File.Exists(_statePath)) return null;
        try { return JsonSerializer.Deserialize<EndpointIsolationSnapshot>(await File.ReadAllTextAsync(_statePath, ct), Json); }
        catch (JsonException) { return null; }
    }

    static ManagementDestination[] Destinations(JsonElement parameters)
    {
        IsolationSafety.ValidateActionParameters(parameters.GetProperty("requestedMode").GetString() switch
        { "isolate" => "endpoint.isolate", "unisolate" => "endpoint.unisolate", _ => "endpoint.isolation_status" }, parameters);
        return parameters.GetProperty("managementDestinations").Deserialize<ManagementDestination[]>()!;
    }

    static string Group(string installation)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(installation))).ToLowerInvariant()[..16];
        return $"OpenSecurityPlatform-Isolation-{hash}";
    }

    static List<string> BuildRules(string group, ManagementDestination[] destinations)
    {
        var commands = new List<string>(); var sequence = 0;
        foreach (var direction in new[] { "outbound", "inbound" })
        {
            var scoped = destinations.Where(x => x.Direction == direction).ToArray();
            foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
            {
                var allowed = scoped.Where(x => Family(x.Address) == family).Select(x => Network(x.Address)).ToArray();
                var blocked = Complement(allowed, family).Select(Format).ToArray();
                if (blocked.Length > 0) commands.Add(NewRule(group, ++sequence, direction, "Any", blocked, null));
                foreach (var address in allowed.Select(Format).Distinct(StringComparer.OrdinalIgnoreCase))
                    foreach (var protocol in new[] { "TCP", "UDP" })
                    {
                        var ports = scoped.Where(x => Family(x.Address) == family &&
                            string.Equals(Format(Network(x.Address)), address, StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(x.Protocol, protocol, StringComparison.OrdinalIgnoreCase)).Select(x => x.Port).Distinct().Order().ToArray();
                        var blockedPorts = PortComplement(ports);
                        if (blockedPorts.Length > 0) commands.Add(NewRule(group, ++sequence, direction, protocol, [address], blockedPorts));
                    }
            }
        }
        return commands;
    }

    static string NewRule(string group, int sequence, string direction, string protocol, string[] addresses, string[]? ports)
    {
        var dir = direction == "outbound" ? "Outbound" : "Inbound";
        var remote = PsArray(addresses);
        var port = ports is { Length: > 0 } ? $" -RemotePort {PsArray(ports)}" : "";
        return $"New-NetFirewallRule -PolicyStore PersistentStore -DisplayName '{group}-{sequence:D3}' -Group '{group}' -Direction {dir} -Action Block -Enabled True -Profile Any -Protocol {protocol} -RemoteAddress {remote}{port} | Out-Null";
    }

    static string PsArray(IEnumerable<string> values) => "@(" + string.Join(',', values.Select(x => $"'{x}'")) + ")";
    static string[] PortComplement(int[] allowed)
    {
        var result = new List<string>(); var start = 1;
        foreach (var port in allowed) { if (port > start) result.Add(port - start == 1 ? start.ToString(System.Globalization.CultureInfo.InvariantCulture) : $"{start}-{port - 1}"); start = port + 1; }
        if (start <= 65535) result.Add(start == 65535 ? "65535" : $"{start}-65535");
        return result.ToArray();
    }

    static AddressFamily Family(string value) => IPAddress.Parse(value.Split('/')[0]).AddressFamily;
    static (BigInteger Start, BigInteger End, int Bits) Network(string value)
    {
        var parts = value.Split('/'); var ip = IPAddress.Parse(parts[0]); var bits = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var prefix = parts.Length == 2 ? int.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture) : bits;
        var number = new BigInteger(ip.GetAddressBytes(), true, true); var host = bits - prefix;
        var mask = host == 0 ? BigInteger.Zero : (BigInteger.One << host) - 1;
        var start = number & ~mask; return (start, start + mask, bits);
    }

    static IEnumerable<(BigInteger Start, BigInteger End, int Bits)> Complement((BigInteger Start, BigInteger End, int Bits)[] allowed, AddressFamily family)
    {
        var bits = family == AddressFamily.InterNetwork ? 32 : 128; var maximum = (BigInteger.One << bits) - 1;
        var merged = new List<(BigInteger Start, BigInteger End)>();
        foreach (var range in allowed.OrderBy(x => x.Start))
        {
            if (merged.Count == 0 || range.Start > merged[^1].End + 1) merged.Add((range.Start, range.End));
            else merged[^1] = (merged[^1].Start, BigInteger.Max(merged[^1].End, range.End));
        }
        var cursor = BigInteger.Zero;
        foreach (var range in merged) { if (range.Start > cursor) yield return (cursor, range.Start - 1, bits); cursor = range.End + 1; }
        if (cursor <= maximum) yield return (cursor, maximum, bits);
    }

    static string Format((BigInteger Start, BigInteger End, int Bits) range)
    {
        var start = Address(range.Start, range.Bits); var end = Address(range.End, range.Bits);
        return start.Equals(end) ? start.ToString() : $"{start}-{end}";
    }
    static IPAddress Address(BigInteger value, int bits)
    {
        var size = bits / 8; var bytes = value.ToByteArray(true, true); var padded = new byte[size];
        bytes.CopyTo(padded.AsSpan(size - bytes.Length)); return new IPAddress(padded);
    }

    static async Task<bool> VerifyManagementAsync(ManagementDestination[] destinations, CancellationToken ct)
    {
        foreach (var destination in destinations.Where(x => x.Direction == "outbound" && x.Protocol == "tcp"))
        {
            var address = destination.Address.Split('/')[0];
            using var client = new TcpClient();
            try { await client.ConnectAsync(IPAddress.Parse(address), destination.Port, ct); }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException) { return false; }
        }
        return true;
    }

    static async Task<int> CountOwnedAsync(string group, CancellationToken ct)
    {
        var output = await PowerShellAsync($"@(Get-NetFirewallRule -PolicyStore PersistentStore -Group '{group}' -ErrorAction SilentlyContinue).Count", ct);
        return int.TryParse(output.Trim(), out var count) ? count : 0;
    }
    static async Task RemoveOwnedAsync(string group, CancellationToken ct) =>
        _ = await PowerShellAsync($"$owned=@(Get-NetFirewallRule -PolicyStore PersistentStore -Group '{group}' -ErrorAction SilentlyContinue);if($owned.Count -gt 0){{$owned|Remove-NetFirewallRule -ErrorAction Stop}};exit 0", ct);

    static async Task<string> PowerShellAsync(string script, CancellationToken ct)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';" + script));
        using var process = new Process { StartInfo = new("powershell.exe") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
        process.StartInfo.ArgumentList.Add("-NoLogo"); process.StartInfo.ArgumentList.Add("-NoProfile"); process.StartInfo.ArgumentList.Add("-NonInteractive"); process.StartInfo.ArgumentList.Add("-EncodedCommand"); process.StartInfo.ArgumentList.Add(encoded);
        process.Start(); var output = await process.StandardOutput.ReadToEndAsync(ct); var error = await process.StandardError.ReadToEndAsync(ct); await process.WaitForExitAsync(ct);
        if (process.ExitCode != 0) throw new InvalidOperationException($"Windows Firewall operation failed safely: {error.Trim()}");
        return output;
    }

    static void EnsureWindowsAdministrator()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Endpoint isolation requires Windows.");
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        if (!new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Endpoint isolation requires an elevated agent service.");
    }
}
