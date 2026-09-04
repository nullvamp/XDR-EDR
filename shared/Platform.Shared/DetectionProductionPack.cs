namespace OpenSecurityPlatform.Foundation;

public sealed record DetectionProductionFixture(
    DetectionDefinition Rule,
    DetectionExclusion Exclusion,
    DetectionRuleTestCase[] Fixtures,
    string Pack,
    string Rationale,
    string[] KnownBenignCases,
    string[] FalsePositiveDrivers,
    string[] TuningGuidance,
    string[] SupportLimitations);

public static class DetectionProductionPack
{
    sealed record Spec(string Key, string Name, string Pack, DetectionDomain Domain, string Tactic,
        string Technique, int Severity, int Confidence, DetectionCondition Condition, string Rationale,
        string[] Benign, string[] Drivers, string[] Tuning, string[] Limits, DetectionRuleType Type = DetectionRuleType.Event,
        int Window = 120, int Threshold = 1, string[]? GroupBy = null, string? DistinctField = null);

    public static IReadOnlyList<DetectionProductionFixture> Create(string tenant)
    {
        var specs = new[]
        {
            S("powershell-encoded", "PowerShell encoded or obfuscated command", "Execution", DetectionDomain.Process, "Execution", "T1059.001", 75, 82, And(Eq("interpreterType","powershell"), Eq("encodedArgument","true"), Eq("hiddenIndicator","true")), "PowerShell is launched with both encoded content and a hidden-execution behavior; an encoded switch alone is insufficient.", ["enterprise deployment scripts"], ["encoded administrative automation"], ["exclude exact signed deployment paths and service accounts"], ["argument decoding is not performed"]),
            S("cmd-network-discovery", "Command shell network discovery", "Discovery", DetectionDomain.Process, "Discovery", "T1016", 55, 72, And(Eq("processName","cmd.exe"), Contains("commandLine","ipconfig")), "Windows shell invokes network configuration discovery.", ["support diagnostics"], ["interactive troubleshooting"], ["scope exclusions to approved support identities"], ["command intent is inferred from arguments"]),
            S("rundll32-script", "Rundll32 script or remote content execution", "Defense Evasion", DetectionDomain.Process, "Defense Evasion", "T1218.011", 80, 86, And(Eq("processName","rundll32.exe"), Contains("commandLine","javascript:")), "Trusted rundll32 proxy executes script content.", ["rare legacy administration"], ["compatibility tooling"], ["allow exact managed command lines only"], ["process telemetry cannot prove payload behavior"]),
            S("regsvr32-scrobj", "Regsvr32 scriptlet proxy execution", "Defense Evasion", DetectionDomain.Process, "Defense Evasion", "T1218.010", 82, 88, And(Eq("processName","regsvr32.exe"), Contains("commandLine","scrobj.dll")), "Regsvr32 invokes the scriptlet execution surface.", ["authorized component registration"], ["legacy installers"], ["exclude signed installer lineage, not regsvr32 globally"], ["network retrieval requires corroborating network evidence"]),
            S("mshta-remote", "Mshta remote content execution", "Defense Evasion", DetectionDomain.Process, "Defense Evasion", "T1218.005", 82, 88, And(Eq("processName","mshta.exe"), Contains("commandLine","http")), "Mshta is launched with a remote resource.", ["legacy intranet applications"], ["approved HTA deployment"], ["allow exact trusted URLs and parent identities"], ["URL reputation is outside this rule"]),
            S("certutil-transfer", "Certutil remote file transfer", "Command and Control", DetectionDomain.Process, "Command and Control", "T1105", 72, 80, And(Eq("processName","certutil.exe"), Contains("commandLine","urlcache")), "Certutil transfer syntax is present in authoritative command-line telemetry.", ["PKI administration"], ["certificate distribution automation"], ["require approved parent and destination in exclusions"], ["successful transfer is not proven"]),
            S("whoami-discovery", "System owner discovery via whoami", "Discovery", DetectionDomain.Process, "Discovery", "T1033", 35, 66, Eq("processName","whoami.exe"), "Native account-context discovery utility executed.", ["logon scripts", "support diagnostics"], ["common interactive use"], ["prefer correlation with unusual parent or remote session"], ["high-volume informational analytic"]),
            S("net-account-discovery", "Local account discovery via net", "Discovery", DetectionDomain.Process, "Discovery", "T1087.001", 45, 70, And(Eq("processName","net.exe"), Contains("commandLine"," user")), "Native utility requests local account information.", ["identity administration"], ["helpdesk workflows"], ["exclude managed identity tooling lineage"], ["domain versus local scope may be ambiguous"]),
            S("tasklist-discovery", "Process discovery via tasklist", "Discovery", DetectionDomain.Process, "Discovery", "T1057", 40, 68, Eq("processName","tasklist.exe"), "Native process enumeration utility executed.", ["support diagnostics"], ["inventory agents"], ["correlate with remote logon or unusual parent"], ["common benign utility"]),
            S("systeminfo-discovery", "System information discovery", "Discovery", DetectionDomain.Process, "Discovery", "T1082", 40, 68, Eq("processName","systeminfo.exe"), "Native system inventory utility executed.", ["inventory and support"], ["configuration management"], ["exclude approved inventory lineage"], ["common benign utility"]),

            S("public-executable-create", "Executable created in public user directory", "Ingress and Staging", DetectionDomain.File, "Command and Control", "T1105", 68, 76, And(Eq("operation","Created"), Starts("path",@"C:\Users\Public\"), Eq("extension",".exe")), "Executable appears in a broadly writable staging location.", ["software distribution"], ["enterprise packaging"], ["allow signer/hash plus managed deployment identity"], ["file creation alone does not prove transfer"]),
            S("user-dll-create", "DLL created in user-writable path", "Defense Evasion", DetectionDomain.File, "Defense Evasion", "T1574.002", 65, 74, And(Eq("operation","Created"), Starts("path",@"C:\Users\"), Eq("extension",".dll")), "DLL materialized in a user-writable path usable for search-order hijacking.", ["developer builds"], ["application self-update"], ["tune exact build roots and trusted signers"], ["load confirmation requires module telemetry"]),
            S("hosts-file-change", "Windows hosts file modification", "Impact and Evasion", DetectionDomain.File, "Impact", "T1565.001", 70, 78, And(Eq("operation","Modified"), Ends("path",@"\System32\drivers\etc\hosts")), "Local name-resolution control data changed.", ["approved network administration"], ["security and VPN clients"], ["allow approved process identity and change window"], ["new file content may be unavailable"]),

            S("run-key-change", "Registry Run key persistence change", "Persistence", DetectionDomain.Registry, "Persistence", "T1547.001", 72, 82, And(Eq("operation","ValueSet"), Contains("path",@"\Software\Microsoft\Windows\CurrentVersion\Run")), "Authoritative registry telemetry records a Run-key write.", ["approved application startup registration"], ["software installation"], ["allow exact publisher, path, value name and maintenance window"], ["value data can be redacted by policy"]),
            S("ifeo-debugger", "IFEO debugger persistence change", "Persistence", DetectionDomain.Registry, "Privilege Escalation", "T1546.012", 88, 90, And(Contains("path",@"\Image File Execution Options\"), Eq("valueName","Debugger"), Eq("operation","ValueSet")), "Debugger redirection is configured under IFEO.", ["authorized debugging"], ["application compatibility testing"], ["allow exact target and debugger within a bounded window"], ["subsequent execution requires process corroboration"]),
            S("defender-exclusion", "Security control exclusion registry change", "Defense Evasion", DetectionDomain.Registry, "Defense Evasion", "T1562.001", 85, 86, And(Contains("path",@"\Windows Defender\Exclusions\"), Eq("operation","ValueSet")), "A security-tool exclusion configuration is written.", ["approved security administration"], ["enterprise policy deployment"], ["allow policy-authority process and expected value hash"], ["product-specific policy may supersede local state"]),

            S("external-uncommon-port", "Outbound connection on uncommon remote-control port", "Command and Control", DetectionDomain.Network, "Command and Control", "T1095", 58, 68, And(Eq("protocol","tcp"), In("destinationPort","4444","1337","31337")), "A process opens TCP to a small bounded set of commonly abused ports.", ["development and laboratory tools"], ["custom business services"], ["tune by destination CIDR and process entity"], ["port alone is weak; correlation is preferred"]),
            S("smb-nonprivate", "SMB connection to non-private destination", "Lateral Movement", DetectionDomain.Network, "Lateral Movement", "T1021.002", 62, 72, And(Eq("protocol","tcp"), Eq("destinationPort","445"), Not(Cidr("destinationIp","10.0.0.0/8"))), "SMB is attempted outside one explicitly private network range.", ["partner networks", "other RFC1918 ranges"], ["hybrid storage"], ["extend tenant-specific private CIDRs before enablement"], ["this rule intentionally does not model every private range"]),

            S("dns-txt-channel", "Unusual DNS TXT query", "DNS and Tunneling", DetectionDomain.Dns, "Command and Control", "T1071.004", 56, 67, Eq("recordType","TXT"), "Process emits a TXT lookup that can support DNS-based application channels.", ["email security", "domain verification"], ["legitimate TXT-heavy services"], ["correlate volume and label diversity before escalation"], ["single TXT queries are low confidence"]),
            S("dns-dynamic-provider", "Query to dynamic DNS provider", "DNS and Tunneling", DetectionDomain.Dns, "Command and Control", "T1071.004", 54, 66, In("query","duckdns.org","no-ip.org","dynu.com"), "Query targets a bounded dynamic-DNS provider inventory.", ["remote access products", "home-lab administration"], ["legitimate dynamic addressing"], ["maintain tenant allowlist and require process attribution"], ["subdomain suffix matching is not available in canonical field today"]),

            S("unsigned-user-module", "Unsigned module loaded from user profile", "Module Integrity", DetectionDomain.Module, "Defense Evasion", "T1574.002", 78, 84, And(Starts("path",@"C:\Users\"), Eq("signerState","unsigned")), "Unsigned image is mapped from a user-writable profile.", ["developer builds", "portable applications"], ["unsigned line-of-business software"], ["allow exact hash and process identity"], ["signature unknown is not treated as unsigned"]),
            S("temp-module-load", "Module loaded from temporary directory", "Module Integrity", DetectionDomain.Module, "Defense Evasion", "T1574.001", 68, 76, Contains("path",@"\AppData\Local\Temp\"), "Image mapping originates from a temporary user location.", ["installers", "application updates"], ["self-extracting packages"], ["correlate signer and parent process; allow exact package hashes"], ["path evidence alone cannot prove hijacking"]),

            S("service-user-path", "Service created from user-writable path", "Services and Tasks", DetectionDomain.Persistence, "Persistence", "T1543.003", 84, 88, And(Eq("kind","Service"), Eq("operation","Created"), Starts("path",@"C:\Users\")), "New Windows service references a user-writable executable.", ["developer test services"], ["nonstandard enterprise deployment"], ["allow exact signed image and deployment actor"], ["start confirmation requires process evidence"]),
            S("task-public-path", "Scheduled task created for public-path payload", "Services and Tasks", DetectionDomain.Persistence, "Persistence", "T1053.005", 78, 84, And(Eq("kind","ScheduledTask"), Eq("operation","Created"), Contains("command",@"C:\Users\Public\")), "New scheduled task invokes a broadly writable path.", ["software deployment"], ["shared maintenance scripts"], ["allow exact task identity, signer and change window"], ["task execution requires process corroboration"]),
            S("wmi-subscription", "WMI permanent event subscription change", "WMI and Autoruns", DetectionDomain.Persistence, "Persistence", "T1546.003", 86, 88, And(Eq("kind","WmiSubscription"), In("operation","Created","Modified")), "Permanent WMI subscription configuration is created or changed.", ["systems management"], ["monitoring automation"], ["allow exact consumer/filter binding and management identity"], ["provider-specific details may be partial"]),

            S("failed-logon-burst", "Repeated failed logons for one account", "Identity", DetectionDomain.Identity, "Credential Access", "T1110", 62, 76, Eq("status","failed"), "Bounded event-time threshold detects repeated authentication failures.", ["password expiry", "user mistakes"], ["health checks with stale credentials"], ["tune threshold by logon type and managed service account"], ["distributed spray needs correlation"], DetectionRuleType.Threshold, 300, 5, ["user"]),
            S("remote-interactive-logon", "Successful remote interactive logon", "Identity", DetectionDomain.Identity, "Lateral Movement", "T1021.001", 52, 70, And(Eq("status","success"), Eq("logonType","10")), "Successful remote-interactive Windows logon is recorded.", ["approved RDP administration"], ["helpdesk access"], ["scope to privileged accounts, unusual sources or time windows"], ["logon type semantics depend on authoritative Windows audit source"]),

            S("remote-thread-start", "Cross-process remote thread start", "Low-level Execution", DetectionDomain.Execution, "Privilege Escalation", "T1055", 90, 90, And(Eq("operation","thread-start"), Exists("sourceProcess"), Exists("targetProcess")), "Low-level telemetry attributes a thread start across process entities.", ["debuggers", "security software"], ["application instrumentation"], ["allow signed tools with exact source-target pairs"], ["source support may report partial attribution"]),
            S("executable-memory", "Executable memory operation", "Low-level Execution", DetectionDomain.Execution, "Defense Evasion", "T1055", 82, 82, And(Eq("executableMemory","true"), Exists("targetProcess")), "Observed low-level operation targets executable memory.", ["JIT runtimes", "browsers"], ["managed runtimes and profilers"], ["require unusual source-target relationship or unsigned module context"], ["allocation intent is not directly observable"]),
            S("process-handle-injection", "Cross-process handle operation with injection relevance", "Low-level Execution", DetectionDomain.Execution, "Privilege Escalation", "T1055", 78, 80, And(Eq("operation","process-handle-requested"), Exists("sourceProcess"), Exists("targetProcess")), "Cross-process handle activity is available for injection-oriented correlation.", ["debuggers", "endpoint security"], ["accessibility and management tooling"], ["tune exact source-target identity and requested-access context"], ["requested access mask is not in the current detection alias set"])
        };
        return specs.Select((spec, index) => Build(tenant, spec, index)).Concat(WindowsExecutionDetectionPack.Create(tenant)).ToArray();
    }

    static Spec S(string key, string name, string pack, DetectionDomain domain, string tactic, string technique,
        int severity, int confidence, DetectionCondition condition, string rationale, string[] benign, string[] drivers,
        string[] tuning, string[] limits, DetectionRuleType type = DetectionRuleType.Event, int window = 120,
        int threshold = 1, string[]? groupBy = null, string? distinctField = null)
        => new(key, name, pack, domain, tactic, technique, severity, confidence, condition, rationale, benign, drivers, tuning, limits, type, window, threshold, groupBy, distinctField);

    static DetectionProductionFixture Build(string tenant, Spec spec, int index)
    {
        var now = DateTimeOffset.UtcNow;
        var id = DetectionDsl.DeterministicId($"sprint32-production-{spec.Key}");
        var version = spec.Key == "powershell-encoded" ? 2 : 1;
        var exclusionId = DetectionDsl.DeterministicId(spec.Key == "powershell-encoded"
            ? $"sprint32-exclusion-{spec.Key}-v{version}"
            : $"sprint32-exclusion-{spec.Key}");
        var endpoint = DetectionDsl.DeterministicId($"sprint32-endpoint-{index}");
        var excludedEndpoint = DetectionDsl.DeterministicId($"sprint32-excluded-endpoint-{index}");
        var conditionFields = Leaves(spec.Condition).Select(x => x.Field!).Distinct(StringComparer.Ordinal).ToArray();
        var required = conditionFields.Concat(["endpointId"]).Distinct(StringComparer.Ordinal).ToArray();
        var groupBy = spec.GroupBy ?? ["endpointId"];
        var rule = new DetectionDefinition("detection-rule.v1", id, version, tenant, spec.Name,
            $"Production Windows analytic. {spec.Rationale}", DetectionRuleStatus.Draft, false, "system:sprint32", now, now,
            spec.Severity, spec.Confidence, spec.Pack, ["production", "windows", "sprint32", Slug(spec.Pack)],
            [spec.Tactic], [spec.Technique], [spec.Domain.ToString()], spec.Type, spec.Domain,
            [$"authoritative {spec.Domain} telemetry", "stable endpoint/entity identity"], required, spec.Window,
            groupBy, spec.Threshold, spec.DistinctField is not null, spec.DistinctField, spec.Condition,
            DetectionExecutionMode.Live, new("detection+endpoint", 15), [exclusionId], "detection-fixture.v2");
        var exclusion = new DetectionExclusion(exclusionId, tenant, 1, $"{spec.Name} controlled endpoint exclusion",
            "endpointId", excludedEndpoint.ToString("D"), true, now.AddMinutes(-5), now.AddDays(30),
            "Exact, time-bounded Sprint 32 quality fixture", "system:sprint32");

        Dictionary<string, string?> Positive(Guid endpointId)
        {
            var fields = new Dictionary<string, string?>(StringComparer.Ordinal) { ["endpointId"] = endpointId.ToString("D") };
            Add(spec.Condition, fields); return fields;
        }
        DetectionEvidenceEvent Event(Dictionary<string, string?> fields, int second, string tenantId = "")
        {
            var eventId = DetectionDsl.DeterministicId($"{tenant}:{spec.Key}:{second}:{string.Join('|', fields.OrderBy(x => x.Key).Select(x => x.Value))}");
            return new(eventId, tenantId.Length == 0 ? tenant : tenantId, spec.Domain, now.AddSeconds(second),
                Guid.TryParse(fields.GetValueOrDefault("endpointId"), out var value) ? value : endpoint,
                $"sprint32-process-{index}", $"sprint32-entity-{index}", fields,
                $"postgresql://platform/sprint32_controlled_events/{eventId:D}", Quality: ["complete"]);
        }
        var positiveFields = Positive(endpoint);
        var negativeFields = new Dictionary<string, string?>(positiveFields, StringComparer.Ordinal);
        var first = Leaves(spec.Condition).First(); negativeFields[first.Field!] = first.Operator == DetectionOperator.Exists ? null : "benign-nonmatch";
        var missingFields = new Dictionary<string, string?>(positiveFields, StringComparer.Ordinal); missingFields.Remove(required[0]);
        var malformedFields = new Dictionary<string, string?>(positiveFields, StringComparer.Ordinal) { [required[0]] = null };
        var excludedFields = Positive(excludedEndpoint);
        var positive = Enumerable.Range(0, spec.Threshold).Select(x => Event(new(positiveFields, StringComparer.Ordinal), x)).ToArray();
        var replay = positive.Concat(positive.Select(x => x with { EventTime = x.EventTime.AddMilliseconds(1) })).ToArray();
        return new(rule, exclusion,
        [
            new($"{spec.Key}-positive", "positive", positive, 1),
            new($"{spec.Key}-negative", "negative", [Event(negativeFields, 20)], 0),
            new($"{spec.Key}-benign", "benign", [Event(malformedFields, 21)], 0),
            new($"{spec.Key}-boundary", "boundary", positive, 1),
            new($"{spec.Key}-missing", "missing-field", [Event(missingFields, 22)], 0),
            new($"{spec.Key}-replay", "replay-duplicate", replay, 1),
            new($"{spec.Key}-suppression", "suppression", replay, 1),
            new($"{spec.Key}-tenant", "tenant-isolation", [Event(positiveFields, 23, Guid.NewGuid().ToString("D"))], 0),
            new($"{spec.Key}-exclusion", "exclusion", [Event(excludedFields, 24)], 0, exclusionId)
        ], spec.Pack, spec.Rationale, spec.Benign, spec.Drivers, spec.Tuning, spec.Limits);
    }

    static IEnumerable<DetectionCondition> Leaves(DetectionCondition condition)
    {
        if (condition.Logic == DetectionLogic.Predicate) { yield return condition; yield break; }
        foreach (var child in condition.Children ?? []) foreach (var leaf in Leaves(child)) yield return leaf;
    }
    static void Add(DetectionCondition condition, IDictionary<string, string?> fields, bool negated = false)
    {
        if (condition.Logic == DetectionLogic.Not)
        {
            foreach (var child in condition.Children ?? []) Add(child, fields, true);
            return;
        }
        if (condition.Logic == DetectionLogic.Predicate && condition.Field is not null)
        {
            fields[condition.Field] = negated ? "203.0.113.10" : condition.Operator switch
            {
                DetectionOperator.Exists => "present",
                DetectionOperator.In => condition.Values![0],
                DetectionOperator.Cidr => condition.Value!.Split('/')[0],
                _ => condition.Value
            }; return;
        }
        foreach (var child in condition.Children ?? []) Add(child, fields, negated);
    }
    static string Slug(string value) => value.ToLowerInvariant().Replace(' ', '-');
    static DetectionCondition Eq(string field, string value) => new(Field: field, Value: value, CaseInsensitive: true);
    static DetectionCondition Contains(string field, string value) => new(Field: field, Operator: DetectionOperator.Contains, Value: value, CaseInsensitive: true);
    static DetectionCondition Starts(string field, string value) => new(Field: field, Operator: DetectionOperator.StartsWith, Value: value, CaseInsensitive: true);
    static DetectionCondition Ends(string field, string value) => new(Field: field, Operator: DetectionOperator.EndsWith, Value: value, CaseInsensitive: true);
    static DetectionCondition In(string field, params string[] values) => new(Field: field, Operator: DetectionOperator.In, Values: values, CaseInsensitive: true);
    static DetectionCondition Exists(string field) => new(Field: field, Operator: DetectionOperator.Exists);
    static DetectionCondition Cidr(string field, string value) => new(Field: field, Operator: DetectionOperator.Cidr, Value: value);
    static DetectionCondition And(params DetectionCondition[] children) => new(DetectionLogic.And, Children: children);
    static DetectionCondition Not(DetectionCondition child) => new(DetectionLogic.Not, Children: [child]);
}
