using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenSecurityPlatform.Foundation;

[JsonConverter(typeof(JsonStringEnumConverter<EndpointIsolationState>))]
public enum EndpointIsolationState
{
    NotIsolated,
    IsolationPending,
    Isolating,
    Isolated,
    PartialIsolation,
    UnisolationPending,
    Unisolating,
    Failed,
    Unknown,
}

[JsonConverter(typeof(JsonStringEnumConverter<IsolationDriftState>))]
public enum IsolationDriftState { None, MissingOwnedControls, UnexpectedOwnedControls, VerificationStale, Unknown }

public sealed record ManagementDestination(
    string Address,
    int Port,
    string Protocol,
    string Direction,
    string Purpose);

public sealed record EndpointIsolationPolicy(
    string SchemaVersion,
    string PolicyVersion,
    ManagementDestination[] ManagementDestinations,
    bool IsolationApprovalRequired,
    bool UnisolationApprovalRequired,
    int PendingExpirySeconds,
    DateTimeOffset CreatedAt,
    string CreatedBy);

public sealed record IsolationActionRequest(
    Guid EndpointId,
    string Reason,
    int ExpiresInSeconds = 900,
    Guid? SourceAlertId = null,
    Guid? SourceIncidentId = null,
    string? SourceEntityId = null);

public sealed record IsolationPolicyUpdate(
    string PolicyVersion,
    ManagementDestination[] ManagementDestinations,
    bool IsolationApprovalRequired = true,
    bool UnisolationApprovalRequired = true,
    int PendingExpirySeconds = 900);

public sealed record IsolationVerification(
    bool OwnedControlsPresent,
    bool ManagementChannelReachable,
    bool ControlledNonManagementBlocked,
    string Result,
    DateTimeOffset VerifiedAt);

public sealed record EndpointIsolationSnapshot(
    string SchemaVersion,
    string TenantId,
    Guid EndpointId,
    string AgentInstallationId,
    EndpointIsolationState RequestedState,
    EndpointIsolationState EffectiveState,
    DateTimeOffset? EffectiveSince,
    DateTimeOffset? LastVerificationTime,
    string PolicyVersion,
    string EnforcementMechanism,
    ManagementDestination[] ManagementExceptions,
    IsolationVerification? Verification,
    string? FailureReason,
    IsolationDriftState DriftState,
    Guid? ActionId,
    string? Requester,
    string? Approver,
    string? Reason,
    Guid? SourceAlertId,
    Guid? SourceIncidentId,
    DateTimeOffset UpdatedAt);

public sealed record IsolationHealth(
    long Requests,
    long SuccessfulIsolation,
    long FailedIsolation,
    long PartialIsolation,
    long Unisolation,
    long VerificationFailures,
    long ManagementChannelFailures,
    long ConflictingActionRejections,
    long ActiveIsolations,
    double AverageIsolationDurationSeconds,
    long DriftDetections,
    DateTimeOffset UpdatedAt);

public static class IsolationSafety
{
    public const string SchemaVersion = "endpoint-isolation.v1";
    public const string DefaultPolicyVersion = "endpoint-isolation-policy.v1";
    public const string EnforcementMechanism = "windows-defender-firewall-owned-rules.v1";
    public const int MaximumDestinations = 32;

    public static EndpointIsolationPolicy DefaultPolicy => new(
        "endpoint-isolation-policy.v1", DefaultPolicyVersion,
        [new("127.0.0.1/32", 8443, "tcp", "outbound", "gateway-control-telemetry-live-response")],
        true, true, 900, DateTimeOffset.UnixEpoch, "platform-default");

    public static void ValidatePolicy(EndpointIsolationPolicy policy)
    {
        if (policy.SchemaVersion != "endpoint-isolation-policy.v1" ||
            string.IsNullOrWhiteSpace(policy.PolicyVersion) || policy.PolicyVersion.Length > 128 ||
            policy.ManagementDestinations.Length is < 1 or > MaximumDestinations ||
            policy.PendingExpirySeconds is < 30 or > 86400)
            throw new EnrollmentConflictException("ISOLATION_POLICY_INVALID", "Isolation policy identity or bounds are invalid.");
        foreach (var destination in policy.ManagementDestinations) ValidateDestination(destination);
        if (policy.ManagementDestinations.Distinct().Count() != policy.ManagementDestinations.Length)
            throw new EnrollmentConflictException("ISOLATION_POLICY_DUPLICATE", "Duplicate management destinations are not allowed.");
    }

    public static void ValidateDestination(ManagementDestination destination)
    {
        var slash = destination.Address.IndexOf('/');
        var addressText = slash < 0 ? destination.Address : destination.Address[..slash];
        if (!IPAddress.TryParse(addressText, out var address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            throw new EnrollmentConflictException("ISOLATION_DESTINATION_ADDRESS", "Management destinations require an exact IP or bounded CIDR, never a wildcard or host name.");
        var maximumPrefix = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        if (slash >= 0 && (!int.TryParse(destination.Address[(slash + 1)..], out var prefix) || prefix is < 0 || prefix > maximumPrefix))
            throw new EnrollmentConflictException("ISOLATION_DESTINATION_CIDR", "Management destination CIDR is invalid.");
        if (destination.Port is < 1 or > 65535 || destination.Protocol is not ("tcp" or "udp") ||
            destination.Direction is not ("outbound" or "inbound") || string.IsNullOrWhiteSpace(destination.Purpose) ||
            destination.Purpose.Length > 128 || destination.Purpose.Any(char.IsControl))
            throw new EnrollmentConflictException("ISOLATION_DESTINATION_BOUNDS", "Management destination protocol, port, direction, or purpose is invalid.");
    }

    public static JsonElement ActionParameters(string mode, string reason, EndpointIsolationPolicy policy)
    {
        ValidatePolicy(policy);
        if (mode is not ("isolate" or "unisolate" or "status") || string.IsNullOrWhiteSpace(reason) || reason.Length > 1024 || reason.Any(char.IsControl))
            throw new EnrollmentConflictException("ISOLATION_REQUEST_INVALID", "Isolation mode or reason is invalid.");
        return JsonSerializer.SerializeToElement(new
        {
            requestedMode = mode,
            reason,
            policyVersion = policy.PolicyVersion,
            managementDestinations = policy.ManagementDestinations,
        });
    }

    public static void ValidateActionParameters(string actionType, JsonElement parameters)
    {
        if (parameters.ValueKind != JsonValueKind.Object) throw new EnrollmentConflictException("ISOLATION_PARAMETERS_INVALID", "Isolation parameters must be an object.");
        var allowed = new HashSet<string>(["requestedMode", "reason", "policyVersion", "managementDestinations"], StringComparer.Ordinal);
        if (parameters.EnumerateObject().Any(x => !allowed.Contains(x.Name))) throw new EnrollmentConflictException("ISOLATION_PARAMETER_UNKNOWN", "Arbitrary isolation/firewall parameters are forbidden.");
        var expected = actionType switch { "endpoint.isolate" => "isolate", "endpoint.unisolate" => "unisolate", "endpoint.isolation_status" => "status", _ => throw new EnrollmentConflictException("ISOLATION_ACTION_INVALID", "Unknown isolation action.") };
        if (!parameters.TryGetProperty("requestedMode", out var mode) || mode.GetString() != expected ||
            !parameters.TryGetProperty("reason", out var reason) || string.IsNullOrWhiteSpace(reason.GetString()) || reason.GetString()!.Length > 1024 ||
            !parameters.TryGetProperty("policyVersion", out var version) || string.IsNullOrWhiteSpace(version.GetString()) || version.GetString()!.Length > 128 ||
            !parameters.TryGetProperty("managementDestinations", out var values) || values.ValueKind != JsonValueKind.Array || values.GetArrayLength() is < 1 or > MaximumDestinations)
            throw new EnrollmentConflictException("ISOLATION_PARAMETERS_INVALID", "Isolation parameters do not match the predefined action contract.");
        foreach (var value in values.EnumerateArray()) ValidateDestination(value.Deserialize<ManagementDestination>() ?? throw new EnrollmentConflictException("ISOLATION_DESTINATION_INVALID", "Management destination is invalid."));
    }

    public static bool IsIsolationAction(string type) => type is "endpoint.isolate" or "endpoint.unisolate" or "endpoint.isolation_status";
}

public interface IIsolationRepository
{
    Task<EndpointIsolationPolicy> PolicyAsync(string tenant, CancellationToken ct);
    Task<EndpointIsolationPolicy> UpdatePolicyAsync(string tenant, string actor, IsolationPolicyUpdate input, CancellationToken ct);
    Task<EndpointIsolationSnapshot?> GetAsync(string tenant, Guid endpoint, CancellationToken ct);
    Task<IReadOnlyList<ResponseActionRecord>> HistoryAsync(string tenant, Guid endpoint, CancellationToken ct);
    Task RecordResultAsync(ResponseActionRecord action, CancellationToken ct);
    Task RecordConflictAsync(string tenant, CancellationToken ct);
    Task<IsolationHealth> HealthAsync(string tenant, CancellationToken ct);
}

public class FileIsolationRepository(IResponseActionRepository actions) : IIsolationRepository
{
    readonly ConcurrentDictionary<string, EndpointIsolationPolicy> _policies = new(StringComparer.Ordinal);
    readonly ConcurrentDictionary<(string Tenant, Guid Endpoint), EndpointIsolationSnapshot> _snapshots = new();
    readonly ConcurrentDictionary<string, long> _conflicts = new(StringComparer.Ordinal);

    protected virtual Task<EndpointIsolationPolicy?> LoadPolicyAsync(string tenant, CancellationToken ct) =>
        Task.FromResult(_policies.TryGetValue(tenant, out var value) ? value : null);
    protected virtual Task SavePolicyAsync(string tenant, EndpointIsolationPolicy value, CancellationToken ct)
    { _policies[tenant] = value; return Task.CompletedTask; }
    protected virtual Task<EndpointIsolationSnapshot?> LoadSnapshotAsync(string tenant, Guid endpoint, CancellationToken ct) =>
        Task.FromResult(_snapshots.TryGetValue((tenant, endpoint), out var value) ? value : null);
    protected virtual Task SaveSnapshotAsync(EndpointIsolationSnapshot value, CancellationToken ct)
    { _snapshots[(value.TenantId, value.EndpointId)] = value; return Task.CompletedTask; }

    public async Task<EndpointIsolationPolicy> PolicyAsync(string tenant, CancellationToken ct) =>
        await LoadPolicyAsync(tenant, ct) ?? IsolationSafety.DefaultPolicy;

    public async Task<EndpointIsolationPolicy> UpdatePolicyAsync(string tenant, string actor, IsolationPolicyUpdate input, CancellationToken ct)
    {
        var value = new EndpointIsolationPolicy("endpoint-isolation-policy.v1", input.PolicyVersion,
            input.ManagementDestinations, input.IsolationApprovalRequired, input.UnisolationApprovalRequired,
            input.PendingExpirySeconds, DateTimeOffset.UtcNow, actor);
        IsolationSafety.ValidatePolicy(value);
        await SavePolicyAsync(tenant, value, ct);
        return value;
    }

    public Task<EndpointIsolationSnapshot?> GetAsync(string tenant, Guid endpoint, CancellationToken ct) =>
        LoadSnapshotAsync(tenant, endpoint, ct);

    public async Task<IReadOnlyList<ResponseActionRecord>> HistoryAsync(string tenant, Guid endpoint, CancellationToken ct)
    {
        var page = await actions.SearchAsync(tenant, endpoint, null, 200, null, ct);
        return page.Items.Where(x => IsolationSafety.IsIsolationAction(x.ActionType)).OrderByDescending(x => x.RequestedAt).ToArray();
    }

    public async Task RecordResultAsync(ResponseActionRecord action, CancellationToken ct)
    {
        if (!IsolationSafety.IsIsolationAction(action.ActionType) || action.Result is null) return;
        EndpointIsolationSnapshot? reported;
        try { reported = action.Result.StructuredResult.Deserialize<EndpointIsolationSnapshot>(); }
        catch (JsonException) { reported = null; }
        var current = await LoadSnapshotAsync(action.TenantId, action.EndpointId, ct);
        EndpointIsolationSnapshot value;
        if (reported is not null && reported.TenantId == action.TenantId && reported.EndpointId == action.EndpointId &&
            reported.AgentInstallationId == action.AgentInstallationId && reported.ActionId == action.ResponseActionId)
        {
            value = reported with
            {
                Requester = action.AnalystId,
                Approver = action.ApproverId,
                SourceAlertId = action.SourceAlertId,
                SourceIncidentId = action.SourceIncidentId,
                UpdatedAt = DateTimeOffset.UtcNow,
            };
        }
        else
        {
            value = new(IsolationSafety.SchemaVersion, action.TenantId, action.EndpointId, action.AgentInstallationId,
                Requested(action.ActionType), EndpointIsolationState.Unknown, current?.EffectiveSince, DateTimeOffset.UtcNow,
                action.PolicyVersion, IsolationSafety.EnforcementMechanism, [], null,
                "Endpoint isolation result did not carry a valid bound state report.", IsolationDriftState.Unknown,
                action.ResponseActionId, action.AnalystId, action.ApproverId, Reason(action.Parameters), action.SourceAlertId,
                action.SourceIncidentId, DateTimeOffset.UtcNow);
        }
        await SaveSnapshotAsync(value, ct);
    }

    public Task RecordConflictAsync(string tenant, CancellationToken ct)
    { _conflicts.AddOrUpdate(tenant, 1, (_, value) => value + 1); return Task.CompletedTask; }

    public async Task<IsolationHealth> HealthAsync(string tenant, CancellationToken ct)
    {
        var page = await actions.SearchAsync(tenant, null, null, 200, null, ct);
        var values = page.Items.Where(x => IsolationSafety.IsIsolationAction(x.ActionType)).ToArray();
        var snapshots = new List<EndpointIsolationSnapshot>();
        foreach (var endpoint in values.Select(x => x.EndpointId).Distinct()) if (await LoadSnapshotAsync(tenant, endpoint, ct) is { } snapshot) snapshots.Add(snapshot);
        var completed = values.Where(x => x.CompletedAt is not null).ToArray();
        var durations = completed.Select(x => (x.CompletedAt!.Value - x.RequestedAt).TotalSeconds).ToArray();
        return new(values.LongCount(x => x.ActionType == "endpoint.isolate"),
            snapshots.LongCount(x => x.EffectiveState == EndpointIsolationState.Isolated),
            values.LongCount(x => x.ActionType == "endpoint.isolate" && x.State == ResponseActionState.Failed),
            snapshots.LongCount(x => x.EffectiveState == EndpointIsolationState.PartialIsolation),
            values.LongCount(x => x.ActionType == "endpoint.unisolate" && x.State == ResponseActionState.Succeeded),
            snapshots.LongCount(x => x.Verification?.Result == "failed"),
            snapshots.LongCount(x => x.Verification is { ManagementChannelReachable: false }),
            _conflicts.GetValueOrDefault(tenant), snapshots.LongCount(x => x.EffectiveState == EndpointIsolationState.Isolated),
            durations.Length == 0 ? 0 : durations.Average(), snapshots.LongCount(x => x.DriftState != IsolationDriftState.None), DateTimeOffset.UtcNow);
    }

    static EndpointIsolationState Requested(string type) => type switch
    { "endpoint.isolate" => EndpointIsolationState.Isolated, "endpoint.unisolate" => EndpointIsolationState.NotIsolated, _ => EndpointIsolationState.Unknown };
    static string? Reason(JsonElement parameters) => parameters.TryGetProperty("reason", out var reason) ? reason.GetString() : null;
}
