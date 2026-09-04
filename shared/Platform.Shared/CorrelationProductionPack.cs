namespace OpenSecurityPlatform.Foundation;

public sealed record CorrelationProductionFixture(CorrelationRule Rule, CorrelationExclusion Exclusion, CorrelationFixture[] Fixtures);

public static class CorrelationProductionPack
{
    public static readonly Guid PackId = CorrelationDsl.DeterministicId("windows-behavioral-detections-pack");

    public static (CorrelationPack Pack, IReadOnlyList<CorrelationProductionFixture> Rules) Create(string tenant)
    {
        var now = DateTimeOffset.UtcNow;
        var specs = new[]
        {
            Spec("rapid-create-execute", "Rapid executable creation followed by execution", CorrelationType.CrossDomain, "Execution", "T1204.002", "endpointId", 120,
                Step("file-create",0,DetectionDomain.File, And(P("operation","Created"),P("extension",".exe"))), Step("execute",1,DetectionDomain.Process,P("path",@"C:\Users\",DetectionOperator.StartsWith))),
            Spec("autorun-then-execute", "Autorun configuration followed by process execution", CorrelationType.CrossDomain, "Persistence", "T1547.001", "endpointId", 300,
                Step("writer",0,DetectionDomain.Process,P("processName","reg.exe")), Step("autorun",1,DetectionDomain.Registry,And(P("operation","ValueSet"),P("path",@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",DetectionOperator.StartsWith))), Step("execute",2,DetectionDomain.Process,P("processName","payload.exe"))),
            Spec("ifeo-debugger-chain", "IFEO debugger configuration followed by target execution", CorrelationType.OrderedSequence, "Persistence", "T1546.012", "endpointId", 600,
                Step("ifeo",0,DetectionDomain.Registry,And(P("path",@"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",DetectionOperator.StartsWith),P("valueName","Debugger"))), Step("target",1,DetectionDomain.Process,P("path",@"C:\Windows\System32\",DetectionOperator.StartsWith))),
            Spec("service-process-chain", "New service configuration followed by service image execution", CorrelationType.CrossDomain, "Persistence", "T1543.003", "endpointId", 300,
                Step("service",0,DetectionDomain.Persistence,And(P("kind","Service"),P("operation","Created"))), Step("process",1,DetectionDomain.Process,P("path",@"C:\ProgramData\",DetectionOperator.StartsWith))),
            Spec("task-process-chain", "Scheduled task creation followed by task image execution", CorrelationType.CrossDomain, "Persistence", "T1053.005", "endpointId", 300,
                Step("task",0,DetectionDomain.Persistence,And(P("kind","ScheduledTask"),P("operation","Created"))), Step("process",1,DetectionDomain.Process,P("path",@"C:\Users\Public\",DetectionOperator.StartsWith))),
            Spec("failed-then-success", "Repeated failed logons followed by success", CorrelationType.ThresholdChain, "Credential Access", "T1110", "user", 600,
                Step("failures",0,DetectionDomain.Identity,P("status","failed"),minimum:3), Step("success",1,DetectionDomain.Identity,P("status","success"))),
            Spec("privileged-logon-process", "Privileged logon followed by sensitive command interpreter", CorrelationType.CrossDomain, "Privilege Escalation", "T1078", "endpointId", 300,
                Step("logon",0,DetectionDomain.Identity,And(P("status","success"),P("logonType","2"))), Step("shell",1,DetectionDomain.Process,P("processName",["powershell.exe","pwsh.exe","cmd.exe"],DetectionOperator.In))),
            Spec("dns-network-chain", "Process DNS query followed by network connection", CorrelationType.CrossDomain, "Command and Control", "T1071.004", "processEntityId", 120,
                Step("process",0,DetectionDomain.Process,P("processName","sprint13-client.exe")), Step("dns",1,DetectionDomain.Dns,P("query",".invalid",DetectionOperator.EndsWith)), Step("connect",2,DetectionDomain.Network,P("protocol","tcp"))),
            Spec("dns-fanout-connect", "Distinct DNS fan-out followed by outbound connection", CorrelationType.DistinctEntity, "Discovery", "T1018", "processEntityId", 300,
                Step("queries",0,DetectionDomain.Dns,P("query",".",DetectionOperator.Contains),minimum:4,distinct:true,distinctField:"query"), Step("connect",1,DetectionDomain.Network,P("protocol","tcp"))),
            Spec("unsigned-module-user-path", "User-writable process followed by unsigned module load", CorrelationType.OrderedSequence, "Defense Evasion", "T1574.002", "processEntityId", 180,
                Step("process",0,DetectionDomain.Process,P("path",@"C:\Users\",DetectionOperator.StartsWith)), Step("module",1,DetectionDomain.Module,And(P("path",@"C:\Users\",DetectionOperator.StartsWith),P("signerState","unsigned")))),
            Spec("module-replace-load", "Module file replacement followed by image load", CorrelationType.CrossDomain, "Defense Evasion", "T1574.002", "endpointId", 180,
                Step("replace",0,DetectionDomain.File,And(P("operation","Modified"),P("extension",".dll"))), Step("load",1,DetectionDomain.Module,P("signerState","unsigned"))),
            Spec("thread-module-context", "Unusual thread start combined with unsigned module context", CorrelationType.UnorderedSet, "Execution", "T1055", "processEntityId", 120,
                Step("thread",0,DetectionDomain.Execution,P("operation","thread-start")), Step("module",0,DetectionDomain.Module,P("signerState","unsigned"))),
            Spec("temp-shell-network", "Command interpreter from writable location followed by connection", CorrelationType.OrderedSequence, "Command and Control", "T1059.001", "processEntityId", 120,
                Step("shell",0,DetectionDomain.Process,And(P("path",@"C:\Users\",DetectionOperator.StartsWith),P("processName",["powershell.exe","pwsh.exe","cmd.exe"],DetectionOperator.In))), Step("connect",1,DetectionDomain.Network,P("protocol","tcp"))),
            Spec("unusual-parent-child", "Unusual parent followed by command interpreter child", CorrelationType.ParentChild, "Execution", "T1059.003", "endpointId", 60,
                Step("parent",0,DetectionDomain.Process,P("processName","winword.exe")), Step("child",1,DetectionDomain.Process,P("processName",["powershell.exe","cmd.exe"],DetectionOperator.In))),
            Spec("finding-accumulation", "Multiple independently evidenced detections accumulate", CorrelationType.FindingToFinding, "Execution", "T1059.001", "endpointId", 300,
                FindingStep("finding-a",0,DetectionDsl.DeterministicId("sprint12-starter-A")), FindingStep("finding-b",1,DetectionDsl.DeterministicId("sprint12-starter-F"))),
            Spec("network-file-transfer", "Outbound connection followed by executable staging", CorrelationType.CrossDomain, "Command and Control", "T1105", "processEntityId", 180,
                Step("connect",0,DetectionDomain.Network,And(P("protocol","tcp"),P("destinationPort",["80","443","8080"],DetectionOperator.In))), Step("stage",1,DetectionDomain.File,And(P("operation","Created"),P("extension",".exe")))),
            Spec("remote-logon-service", "Remote interactive logon followed by service creation", CorrelationType.OrderedSequence, "Lateral Movement", "T1021.001", "endpointId", 300,
                Step("logon",0,DetectionDomain.Identity,And(P("status","success"),P("logonType","10"))), Step("service",1,DetectionDomain.Persistence,And(P("kind","Service"),P("operation","Created")))),
            Spec("dns-txt-connect", "DNS TXT activity followed by outbound connection", CorrelationType.CrossDomain, "Command and Control", "T1071.004", "processEntityId", 120,
                Step("dns",0,DetectionDomain.Dns,P("recordType","TXT"),minimum:3), Step("connect",1,DetectionDomain.Network,P("protocol","tcp"))),
            Spec("script-create-execute", "Script creation followed by interpreter execution", CorrelationType.CrossDomain, "Execution", "T1059", "filePathArgument", 120,
                Step("script",0,DetectionDomain.File,And(P("operation","Created"),P("extension",[".ps1",".vbs",".js",".hta",".cmd",".bat"],DetectionOperator.In))), Step("interpreter",1,DetectionDomain.Process,And(P("interpreterType",["powershell","cmd","wscript","cscript","mshta"],DetectionOperator.In),P("userWritableArgument","true")))),
            Spec("executable-create-execute", "Writable executable creation followed by suspicious execution", CorrelationType.CrossDomain, "Execution", "T1204.002", "filePathArgument", 120,
                Step("executable",0,DetectionDomain.File,And(P("operation","Created"),P("extension",".exe"))), Step("process",1,DetectionDomain.Process,And(P("path",@"\Users\",DetectionOperator.Contains),P("signed","false")))),
            Spec("browser-writable-payload", "Browser launches writable payload", CorrelationType.ParentChild, "Execution", "T1204.002", "endpointId", 60,
                Step("browser",0,DetectionDomain.Process,P("processName",["chrome.exe","msedge.exe","firefox.exe","brave.exe"],DetectionOperator.In)), Step("payload",1,DetectionDomain.Process,And(P("path",@"\Users\",DetectionOperator.Contains),P("signed","false")))),
            Spec("office-interpreter-chain", "Office launches suspicious interpreter", CorrelationType.ParentChild, "Execution", "T1204.002", "endpointId", 60,
                Step("office",0,DetectionDomain.Process,P("processName",["winword.exe","excel.exe","powerpnt.exe","outlook.exe"],DetectionOperator.In)), Step("interpreter",1,DetectionDomain.Process,And(P("interpreterType",["powershell","cmd","wscript","cscript","mshta"],DetectionOperator.In),P("suspiciousSwitch","true")))),
            Spec("retrieval-stage-execute", "Retrieval-like command stages and executes a payload", CorrelationType.CrossDomain, "Command and Control", "T1105", "filePathArgument", 180,
                Step("retrieval",0,DetectionDomain.Process,P("retrievalIndicator","true")), Step("stage",1,DetectionDomain.File,P("operation","Created")), Step("execute",2,DetectionDomain.Process,And(P("path",@"\Users\",DetectionOperator.Contains),P("signed","false")))),
            Spec("suspicious-execution-network", "Suspicious interpreter followed by DNS and network activity", CorrelationType.CrossDomain, "Command and Control", "T1071", "processEntityId", 120,
                Step("execute",0,DetectionDomain.Process,And(P("suspiciousSwitch","true"),P("executionIndicator","true"))), Step("dns",1,DetectionDomain.Dns,P("query",".",DetectionOperator.Contains)), Step("network",2,DetectionDomain.Network,P("protocol","tcp"))),
            Spec("execution-persistence-chain", "Suspicious execution followed by persistence configuration", CorrelationType.CrossDomain, "Persistence", "T1547.001", "endpointId", 300,
                Step("execute",0,DetectionDomain.Process,And(P("suspiciousSwitch","true"),P("userWritableArgument","true"))), Step("persistence",1,DetectionDomain.Persistence,P("operation",["Created","Modified","ValueSet"],DetectionOperator.In))),
            Spec("nested-interpreter-chain", "Native nested interpreter chain", CorrelationType.ParentChild, "Execution", "T1059", "endpointId", 60,
                Step("parent",0,DetectionDomain.Process,P("interpreterType",["powershell","cmd","mshta"],DetectionOperator.In)), Step("child",1,DetectionDomain.Process,And(P("interpreterType",["powershell","cmd","mshta"],DetectionOperator.In),P("obfuscationIndicator","true")))),
            Spec("lolbin-network-chain", "Suspicious signed-binary proxy execution followed by network", CorrelationType.CrossDomain, "Defense Evasion", "T1218", "processEntityId", 120,
                Step("proxy",0,DetectionDomain.Process,And(P("processName",["rundll32.exe","regsvr32.exe","mshta.exe","certutil.exe","bitsadmin.exe","msiexec.exe","cmstp.exe","installutil.exe","regasm.exe","regsvcs.exe"],DetectionOperator.In),P("retrievalIndicator","true"))), Step("network",1,DetectionDomain.Network,P("protocol","tcp"))),
            Spec("execution-toolchain-burst", "Suspicious command toolchain burst", CorrelationType.ThresholdChain, "Execution", "T1059", "endpointId", 180,
                Step("shells",0,DetectionDomain.Process,P("interpreterType",["powershell","cmd","wscript","cscript","mshta"],DetectionOperator.In),minimum:3), Step("context",1,DetectionDomain.Process,P("suspiciousSwitch","true")))
        };
        var rules = specs.Select((spec, i) => Build(tenant, now, spec, i)).ToArray();
        var pack = new CorrelationPack(PackId, 3, tenant, "Windows Behavioral Correlation Pack", "Production-oriented evidence-backed Windows behavioral correlations expanded with Sprint 39 execution-depth chains.", Enum.GetValues<DetectionDomain>(), rules.Select(x => x.Rule.CorrelationRuleId).ToArray(), rules.Select(x => x.Rule.MitreTechnique).Distinct().ToArray(), ["Sprint 12 detection-engine.v1", "canonical telemetry schemas", "Sprint 39 bounded command-line features"], true, false, "v3: 28 tested behavioral correlations including ten execution-depth chains", now, "system:sprint39");
        return (pack, rules);
    }

    sealed record RuleSpec(string Key, string Name, CorrelationType Type, string Tactic, string Technique, string JoinKey, int Window, CorrelationStep[] Steps);
    static RuleSpec Spec(string key, string name, CorrelationType type, string tactic, string technique, string join, int window, params CorrelationStep[] steps) => new(key, name, type, tactic, technique, join, window, steps);
    static CorrelationStep Step(string id, int order, DetectionDomain domain, DetectionCondition condition, int minimum = 1, bool distinct = false, string? distinctField = null) => new(id, order, CorrelationInputKind.Event, domain, condition, true, false, minimum, distinct, distinctField);
    static CorrelationStep FindingStep(string id, int order, Guid detection) => new(id, order, CorrelationInputKind.DetectionFinding, null, new(Field: "endpointId", Operator: DetectionOperator.Exists), true, false, 1, false, null, 0, detection);
    static DetectionCondition P(string field, string value, DetectionOperator op = DetectionOperator.Equal) => new(Field: field, Operator: op, Value: value, CaseInsensitive: true);
    static DetectionCondition P(string field, string[] values, DetectionOperator op) => new(Field: field, Operator: op, Values: values, CaseInsensitive: true);
    static DetectionCondition And(params DetectionCondition[] children) => new(DetectionLogic.And, Children: children);

    static CorrelationProductionFixture Build(string tenant, DateTimeOffset now, RuleSpec spec, int index)
    {
        var id = CorrelationDsl.DeterministicId($"sprint13-production-{spec.Key}"); var exclusionId = CorrelationDsl.DeterministicId($"sprint13-exclusion-{spec.Key}");
        var domains = spec.Steps.Where(x => x.Domain is not null).Select(x => x.Domain!.Value).Distinct().ToArray();
        var quality = new CorrelationQuality($"Correlates independently authoritative evidence for {spec.Name.ToLowerInvariant()}.", ["Administrator-approved software deployment", "enterprise management tooling"], "Tune exact paths, users, endpoints and maintenance windows; never disable the pack globally.", ["software installation", "logon testing", "administrative automation"], "Base confidence reflects multiple independently persisted observations and is reduced for late/incomplete telemetry.", ["Windows telemetry only", "does not depend on unobservable Sprint 11 memory/creator surfaces"]);
        var rule = new CorrelationRule("correlation-rule.v1", id, 1, tenant, PackId, 3, spec.Name, $"Production-oriented Windows behavioral correlation: {spec.Name}.", 70 + index % 3 * 5, 80, spec.Key, ["production", "windows", "evidence-first", index >= 18 ? "sprint39" : "sprint32"], spec.Tactic, spec.Technique, spec.Technique.Contains('.') ? spec.Technique : null, domains, spec.Steps.Where(x => x.DetectionId is not null).Select(x => x.DetectionId!.Value).ToArray(), spec.JoinKey, spec.Type, spec.Window, [spec.JoinKey], spec.Steps, new("correlation-key", 15), [exclusionId], quality, CorrelationStatus.Draft, false, false, null, now, index >= 18 ? "system:sprint39" : "system:sprint32");
        var exclusion = new CorrelationExclusion(exclusionId, 1, tenant, PackId, id, spec.JoinKey, $"sprint13-excluded-{index}", now.AddMinutes(-5), now.AddDays(30), "Bounded production-pack tuning fixture", "system:sprint13");
        var endpoint = CorrelationDsl.DeterministicId($"sprint13-endpoint-{index}"); var process = $"sprint13-process-{index}"; var user = $"sprint13-user-{index}";
        var positive = spec.Steps.Where(x => !x.Negative).SelectMany((step, stepIndex) => Enumerable.Range(0, step.MinimumCount).Select(n => Observation(tenant, rule, step, endpoint, process, user, now.AddSeconds(stepIndex * 5 + n), false, index, n))).ToArray();
        var negative = positive.Where(x => x.ObservationId != positive[^1].ObservationId).ToArray();
        var boundary = positive.Select((x, i) => x with { EventTime = i == positive.Length - 1 ? positive[0].EventTime.AddSeconds(spec.Window) : x.EventTime }).ToArray();
        var missing = positive.Where(x => x.ObservationId != positive[^1].ObservationId).ToArray();
        var foreign = positive.Select(x => x with { TenantId = CorrelationDsl.DeterministicId($"foreign:{tenant}").ToString("D") }).ToArray();
        return new(rule, exclusion,
        [
            new($"{spec.Key}-positive", "positive", positive, 1),
            new($"{spec.Key}-negative", "negative", negative, 0),
            new($"{spec.Key}-benign", "benign", negative, 0),
            new($"{spec.Key}-boundary", "boundary", boundary, 1),
            new($"{spec.Key}-missing", "missing-field", missing, 0),
            new($"{spec.Key}-replay", "replay-duplicate", positive.Concat(positive).ToArray(), 1),
            new($"{spec.Key}-tenant", "tenant-isolation", foreign, 0),
            new($"{spec.Key}-out-of-order", "out-of-order", positive.Reverse().ToArray(), 1)
        ]);
    }

    static CorrelationObservation Observation(string tenant, CorrelationRule rule, CorrelationStep step, Guid endpoint, string process, string user, DateTimeOffset at, bool benign, int index, int occurrence)
    {
        var fields = new Dictionary<string, string?>(StringComparer.Ordinal) { ["endpointId"] = endpoint.ToString("D"), ["processEntityId"] = process, ["user"] = user };
        if (rule.JoinKeys.Contains("filePathArgument", StringComparer.OrdinalIgnoreCase)) fields["filePathArgument"] = $@"c:\users\public\sprint39-artifact-{index}.exe";
        Add(step.Condition, fields, benign); if (step.Distinct && step.DistinctField is not null) fields[step.DistinctField] = $"{fields.GetValueOrDefault(step.DistinctField)}{occurrence}.invalid"; var id = CorrelationDsl.DeterministicId($"{tenant}:{rule.CorrelationRuleId}:{step.Id}:{at:O}:{occurrence}");
        var processId = rule.Type == CorrelationType.ParentChild && step.Order > 0 ? $"child-{process}" : process; var parentId = rule.Type == CorrelationType.ParentChild && step.Order > 0 ? process : $"parent-{process}";
        return new(id, tenant, step.InputKind, step.Domain, at, at.AddMilliseconds(25), endpoint, processId, parentId, $"entity-{index}", step.InputKind == CorrelationInputKind.DetectionFinding ? id : null, step.DetectionId, fields, $"postgresql://platform/sprint13_fixture_observations/{id:D}", Quality: ["complete"], Confidence: 10);
    }
    static void Add(DetectionCondition condition, Dictionary<string, string?> fields, bool benign)
    {
        if (condition.Logic == DetectionLogic.Predicate && condition.Field is not null) { if (condition.Operator != DetectionOperator.Exists) fields[condition.Field] = benign ? "benign" : condition.Operator == DetectionOperator.In ? condition.Values![0] : condition.Value; return; }
        foreach (var child in condition.Children ?? []) Add(child, fields, benign);
    }
}
