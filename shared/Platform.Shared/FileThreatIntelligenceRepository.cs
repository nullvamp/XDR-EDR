using System.Text;
using System.Text.Json;

namespace OpenSecurityPlatform.Foundation;

public sealed class FileThreatIntelligenceRepository : IThreatIntelligenceRepository, IThreatIntelligenceProjection
{
    readonly object _gate = new();
    readonly List<IntelligenceSource> _sources = [];
    readonly List<ThreatIndicator> _indicators = [];
    readonly List<ThreatMatch> _matches = [];
    readonly List<ThreatExclusion> _exclusions = [];
    readonly List<ThreatBackmatchJob> _jobs = [];
    long _imports, _importFailures, _invalid, _duplicates;
    double _latency;

    public FileThreatIntelligenceRepository() { }
    public FileThreatIntelligenceRepository(IEnumerable<IntelligenceSource> sources,
        IEnumerable<ThreatIndicator> indicators, IEnumerable<ThreatMatch> matches,
        IEnumerable<ThreatExclusion> exclusions, IEnumerable<ThreatBackmatchJob> jobs)
    {
        _sources.AddRange(sources); _indicators.AddRange(indicators); _matches.AddRange(matches);
        _exclusions.AddRange(exclusions); _jobs.AddRange(jobs);
    }
    public IReadOnlyList<ThreatIndicator> SnapshotIndicators(string tenant) { lock (_gate) return _indicators.Where(x => x.TenantId == tenant).ToArray(); }

    public Task<IntelligenceSource> CreateSourceAsync(string tenant, IntelligenceSource source, string actor, CancellationToken ct)
    {
        lock (_gate)
        {
            if (source.GlobalScope) throw new EnrollmentConflictException("INTEL_GLOBAL_SCOPE_FORBIDDEN", "Global sources require a separate platform authorization path.");
            if (_sources.Any(x => x.TenantId == tenant && string.Equals(x.Name, source.Name, StringComparison.OrdinalIgnoreCase))) throw new EnrollmentConflictException("INTEL_SOURCE_EXISTS", "Source name already exists.");
            var now = DateTimeOffset.UtcNow; var value = source with { SourceId = source.SourceId == Guid.Empty ? Guid.NewGuid() : source.SourceId, TenantId = tenant, Reliability = Math.Clamp(source.Reliability, 0, 100), DefaultConfidence = Math.Clamp(source.DefaultConfidence, 0, 100), RateLimitPerMinute = Math.Clamp(source.RateLimitPerMinute, 1, 10_000), CreatedAt = now, UpdatedAt = now, Version = 1 };
            _sources.Add(value); return Task.FromResult(value);
        }
    }
    public Task<IReadOnlyList<IntelligenceSource>> SourcesAsync(string tenant, CancellationToken ct) { lock (_gate) return Task.FromResult<IReadOnlyList<IntelligenceSource>>(_sources.Where(x => x.TenantId == tenant).OrderBy(x => x.Name).ToArray()); }
    public Task<ThreatIndicator> AddAsync(string tenant, ThreatIndicatorInput input, string actor, CancellationToken ct)
    {
        lock (_gate)
        {
            var source = _sources.FirstOrDefault(x => x.TenantId == tenant && x.SourceId == input.SourceId) ?? throw new KeyNotFoundException("Intelligence source not found.");
            string canonical; try { canonical = ThreatIntelligenceSafety.Normalize(input.Type, input.Value); } catch { _invalid++; throw; }
            var now = DateTimeOffset.UtcNow; var validFrom = input.ValidFrom ?? now;
            if (input.ValidUntil is { } until && until <= validFrom) throw new EnrollmentConflictException("IOC_VALIDITY_INVALID", "Valid-until must be after valid-from.");
            var identity = ThreatIntelligenceSafety.StableId(tenant, input.SourceId.ToString("D"), input.Type.ToString(), canonical, input.SourceRecordId ?? "");
            var history = _indicators.Where(x => x.TenantId == tenant && x.IndicatorId == identity).ToArray();
            if (history.Any(x => x.SourceVersion == input.SourceVersion && x.CanonicalValue == canonical)) { _duplicates++; return Task.FromResult(history.MaxBy(x => x.Version)!); }
            var version = history.Length == 0 ? 1 : history.Max(x => x.Version) + 1;
            var value = new ThreatIndicator(identity, tenant, source.SourceId, input.SourceRecordId, version, input.SourceVersion, input.Type, canonical, input.Value, canonical, Math.Clamp(input.Confidence ?? source.DefaultConfidence, 0, 100), Math.Clamp(input.Reliability ?? source.Reliability, 0, 100), input.Severity is { } severity ? Math.Clamp(severity, 0, 100) : null, input.FirstSeen, input.LastSeen, validFrom, input.ValidUntil, input.Revoked, input.ValidUntil <= now, input.Tags ?? [], input.Tlp, input.Campaign, input.MalwareFamily, input.ThreatActor, input.AttackMappings ?? [], input.SourceReference, ThreatIntelligenceSafety.NormalizationVersion, $"{input.Provenance};actor={actor};source={source.Name};sourceVersion={input.SourceVersion ?? "none"}", now, now);
            _indicators.Add(value); return Task.FromResult(value);
        }
    }
    public async Task<ThreatImportResult> ImportAsync(string tenant, Guid sourceId, string format, Stream content, string actor, CancellationToken ct)
    {
        if (!content.CanSeek) { var copy = new MemoryStream(); await content.CopyToAsync(copy, ct); copy.Position = 0; content = copy; }
        if (content.Length > ThreatIntelligenceSafety.MaximumImportBytes) { _importFailures++; throw new EnrollmentConflictException("INTEL_IMPORT_TOO_LARGE", "Import exceeds 5 MiB."); }
        using var reader = new StreamReader(content, new UTF8Encoding(false, true), false, 8192, true); var text = await reader.ReadToEndAsync(ct);
        var rows = ThreatImportParser.Parse(format, text); if (rows.Count > ThreatIntelligenceSafety.MaximumImportRecords) { _importFailures++; throw new EnrollmentConflictException("INTEL_IMPORT_RECORD_LIMIT", "Import exceeds 10,000 records."); }
        var imported = 0; var duplicateStart = _duplicates; var errors = new List<string>();
        for (var i = 0; i < rows.Count; i++) try { await AddAsync(tenant, rows[i] with { SourceId = sourceId }, actor, ct); imported++; } catch (Exception e) when (e is EnrollmentConflictException or FormatException or JsonException) { errors.Add($"record {i + 1}: {e.Message}"); if (errors.Count >= 100) break; }
        _imports++; if (errors.Count > 0) _importFailures++; var duplicates = (int)(_duplicates - duplicateStart); imported -= duplicates;
        return new(Guid.NewGuid(), rows.Count, imported, duplicates, errors.Count, errors.ToArray(), DateTimeOffset.UtcNow);
    }
    public Task<ThreatPage<ThreatIndicator>> SearchAsync(string tenant, ThreatSearchRequest q, CancellationToken ct)
    {
        if (q.PageSize is < 1 or > 500 || q.Cursor is not null) throw new EnrollmentConflictException("INTEL_QUERY_INVALID", "Page size or cursor is invalid.");
        lock (_gate) { var now = DateTimeOffset.UtcNow; var latest = _indicators.Where(x => x.TenantId == tenant).GroupBy(x => x.IndicatorId).Select(x => x.MaxBy(v => v.Version)!).Where(x => (q.Type is null || x.Type == q.Type) && (q.SourceId is null || x.SourceId == q.SourceId) && (q.Active is null || x.ActiveAt(now) == q.Active) && (string.IsNullOrWhiteSpace(q.Query) || x.CanonicalValue.Contains(q.Query, StringComparison.OrdinalIgnoreCase) || x.Tags.Any(t => t.Contains(q.Query, StringComparison.OrdinalIgnoreCase)))).OrderByDescending(x => x.UpdatedAt).ThenBy(x => x.IndicatorId).ToArray(); return Task.FromResult(new ThreatPage<ThreatIndicator>(latest.Take(q.PageSize).ToArray(), null, latest.LongLength)); }
    }
    public Task<ThreatIndicator?> GetAsync(string tenant, Guid id, int? version, CancellationToken ct) { lock (_gate) return Task.FromResult(_indicators.Where(x => x.TenantId == tenant && x.IndicatorId == id && (version is null || x.Version == version)).MaxBy(x => x.Version)); }
    public Task<ThreatIndicator> SetStateAsync(string tenant, Guid id, bool? revoked, DateTimeOffset? validUntil, string actor, CancellationToken ct)
    {
        lock (_gate) { var prior = _indicators.Where(x => x.TenantId == tenant && x.IndicatorId == id).MaxBy(x => x.Version) ?? throw new KeyNotFoundException(); var now = DateTimeOffset.UtcNow; var value = prior with { Version = prior.Version + 1, Revoked = revoked ?? prior.Revoked, ValidUntil = validUntil ?? prior.ValidUntil, Expired = (validUntil ?? prior.ValidUntil) <= now, Provenance = $"{prior.Provenance};state-change={actor}", UpdatedAt = now }; _indicators.Add(value); return Task.FromResult(value); }
    }
    public Task<IReadOnlyList<ThreatMatch>> MatchAsync(string tenant, IReadOnlyList<ThreatEvidence> evidence, ThreatMatchMode mode, CancellationToken ct)
    {
        var started = System.Diagnostics.Stopwatch.GetTimestamp(); lock (_gate)
        {
            var now = DateTimeOffset.UtcNow; var active = _indicators.Where(x => x.TenantId == tenant).GroupBy(x => x.IndicatorId).Select(x => x.MaxBy(v => v.Version)!).Where(x => x.ActiveAt(now)).ToArray(); var created = new List<ThreatMatch>();
            foreach (var ev in evidence.Take(256)) foreach (var indicator in active.Where(x => x.Type == ev.Type || x.Type == ThreatIndicatorType.Cidr && ev.Type is ThreatIndicatorType.IPv4 or ThreatIndicatorType.IPv6))
                {
                    if (!ThreatIntelligenceSafety.Matches(indicator, ev)) continue; var exclusion = ActiveExclusion(tenant, indicator, ev, now);
                    var id = ThreatIntelligenceSafety.StableId(tenant, indicator.IndicatorId.ToString("D"), indicator.Version.ToString(System.Globalization.CultureInfo.InvariantCulture), ev.EventId.ToString("D"), ev.Field, mode.ToString());
                    var existing = _matches.FirstOrDefault(x => x.MatchId == id); if (existing is not null) { created.Add(existing); continue; }
                    var match = new ThreatMatch(id, tenant, indicator.IndicatorId, indicator.Version, indicator.SourceId, ev.EventId, ev.EntityId, ev.EndpointId, ev.ProcessEntityId, ev.Field, ThreatIntelligenceSafety.Normalize(ev.Type, ev.Value), indicator.Type, ev.ObservedAt, ev.ObservedAt, indicator.Confidence, ev.Quality, mode, ThreatIntelligenceSafety.EngineVersion, ev.EvidenceReference, exclusion is not null, exclusion?.ExclusionId, now); _matches.Add(match); created.Add(match);
                }
            _latency = System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds; return Task.FromResult<IReadOnlyList<ThreatMatch>>(created);
        }
    }
    ThreatExclusion? ActiveExclusion(string tenant, ThreatIndicator i, ThreatEvidence e, DateTimeOffset now) => _exclusions.Where(x => x.TenantId == tenant && x.Enabled && x.ValidFrom <= now && (x.ValidUntil is null || x.ValidUntil > now)).OrderByDescending(x => x.Version).FirstOrDefault(x => x.Scope switch { ThreatExclusionScope.Endpoint => x.Value == e.EndpointId.ToString("D"), ThreatExclusionScope.Process => x.Value == e.ProcessEntityId, ThreatExclusionScope.Indicator => x.Value == i.IndicatorId.ToString("D"), ThreatExclusionScope.Source => x.Value == i.SourceId.ToString("D"), ThreatExclusionScope.Entity => x.Value == e.EntityId, ThreatExclusionScope.Domain => i.Type is ThreatIndicatorType.Domain or ThreatIndicatorType.Hostname && x.Value == i.CanonicalValue, ThreatExclusionScope.Ip => i.Type is ThreatIndicatorType.IPv4 or ThreatIndicatorType.IPv6 or ThreatIndicatorType.Cidr && x.Value == i.CanonicalValue, ThreatExclusionScope.FileHash => i.Type is ThreatIndicatorType.Sha256 or ThreatIndicatorType.Sha1 or ThreatIndicatorType.Md5 && x.Value == i.CanonicalValue, _ => false });
    public Task<ThreatPage<ThreatMatch>> SearchMatchesAsync(string tenant, ThreatMatchSearchRequest q, CancellationToken ct) { if (q.PageSize is < 1 or > 500 || q.Cursor is not null) throw new EnrollmentConflictException("INTEL_QUERY_INVALID", "Page size or cursor is invalid."); lock (_gate) { var values = _matches.Where(x => x.TenantId == tenant && (q.IndicatorId is null || x.IndicatorId == q.IndicatorId) && (q.EndpointId is null || x.EndpointId == q.EndpointId) && (q.EvidenceEventId is null || x.EvidenceEventId == q.EvidenceEventId) && (q.Mode is null || x.Mode == q.Mode)).OrderByDescending(x => x.LastSeen).ThenBy(x => x.MatchId).ToArray(); return Task.FromResult(new ThreatPage<ThreatMatch>(values.Take(q.PageSize).ToArray(), null, values.LongLength)); } }
    public Task<ThreatExclusion> AddExclusionAsync(string tenant, ThreatExclusion x, string actor, CancellationToken ct) { if (x.ValidUntil is { } until && until <= x.ValidFrom) throw new EnrollmentConflictException("INTEL_EXCLUSION_INVALID", "Exclusion validity is invalid."); lock (_gate) { var version = _exclusions.Where(e => e.TenantId == tenant && e.ExclusionId == x.ExclusionId).Select(e => e.Version).DefaultIfEmpty().Max() + 1; var value = x with { ExclusionId = x.ExclusionId == Guid.Empty ? Guid.NewGuid() : x.ExclusionId, TenantId = tenant, Version = version, Actor = actor, CreatedAt = DateTimeOffset.UtcNow }; _exclusions.Add(value); return Task.FromResult(value); } }
    public Task<IReadOnlyList<ThreatExclusion>> ExclusionsAsync(string tenant, CancellationToken ct) { lock (_gate) return Task.FromResult<IReadOnlyList<ThreatExclusion>>(_exclusions.Where(x => x.TenantId == tenant).GroupBy(x => x.ExclusionId).Select(x => x.MaxBy(v => v.Version)!).ToArray()); }
    public Task<ThreatBackmatchJob> QueueBackmatchAsync(string tenant, Guid indicatorId, int version, DateTimeOffset from, DateTimeOffset until, ThreatMatchMode mode, string actor, CancellationToken ct) { if (until <= from || until - from > TimeSpan.FromDays(ThreatIntelligenceSafety.MaximumBackmatchDays) || mode == ThreatMatchMode.Live) throw new EnrollmentConflictException("INTEL_BACKMATCH_BOUNDS", "Historical backmatch requires a positive range of at most 31 days and a non-live mode."); lock (_gate) { if (!_indicators.Any(x => x.TenantId == tenant && x.IndicatorId == indicatorId && x.Version == version)) throw new KeyNotFoundException(); var id = ThreatIntelligenceSafety.StableId(tenant, indicatorId.ToString("D"), version.ToString(System.Globalization.CultureInfo.InvariantCulture), from.ToUniversalTime().ToString("O"), until.ToUniversalTime().ToString("O"), mode.ToString()); var existing = _jobs.FirstOrDefault(x => x.JobId == id); if (existing is not null) return Task.FromResult(existing); var now = DateTimeOffset.UtcNow; var value = new ThreatBackmatchJob(id, tenant, indicatorId, version, from, until, mode, ThreatJobState.Queued, 0, 0, 0, null, actor, now, now); _jobs.Add(value); return Task.FromResult(value); } }
    public Task<ThreatBackmatchJob?> GetJobAsync(string tenant, Guid jobId, CancellationToken ct) { lock (_gate) return Task.FromResult(_jobs.FirstOrDefault(x => x.TenantId == tenant && x.JobId == jobId)); }
    public Task<ThreatBackmatchJob?> CancelJobAsync(string tenant, Guid jobId, string actor, CancellationToken ct) { lock (_gate) { var index = _jobs.FindIndex(x => x.TenantId == tenant && x.JobId == jobId); if (index < 0) return Task.FromResult<ThreatBackmatchJob?>(null); var value = _jobs[index] with { State = ThreatJobState.Cancelled, UpdatedAt = DateTimeOffset.UtcNow }; _jobs[index] = value; return Task.FromResult<ThreatBackmatchJob?>(value); } }
    public Task<ThreatHealth> HealthAsync(string tenant, CancellationToken ct) { lock (_gate) { var now = DateTimeOffset.UtcNow; var latest = _indicators.Where(x => x.TenantId == tenant).GroupBy(x => x.IndicatorId).Select(x => x.MaxBy(v => v.Version)!).ToArray(); return Task.FromResult(new ThreatHealth(_sources.LongCount(x => x.TenantId == tenant), latest.LongCount(x => x.ActiveAt(now)), latest.LongCount(x => !x.Revoked && x.ValidUntil <= now), latest.LongCount(x => x.Revoked), _imports, _importFailures, _matches.LongCount(x => x.TenantId == tenant), _matches.LongCount(x => x.TenantId == tenant && x.Excluded), _jobs.LongCount(x => x.TenantId == tenant), _invalid, _duplicates, _latency, now)); } }
    Task<(long IndicatorVersions, long Matches)> IThreatIntelligenceRepository.CountsAsync(string tenant, CancellationToken ct) { lock (_gate) return Task.FromResult((_indicators.LongCount(x => x.TenantId == tenant), _matches.LongCount(x => x.TenantId == tenant))); }
    public Task EnsureAsync(CancellationToken ct) => Task.CompletedTask;
    public Task UpsertIndicatorAsync(ThreatIndicator indicator, CancellationToken ct) => Task.CompletedTask;
    public Task UpsertMatchAsync(ThreatMatch match, CancellationToken ct) => Task.CompletedTask;
    public Task<(long Indicators, long Matches)> CountsAsync(string tenant, CancellationToken ct) { lock (_gate) return Task.FromResult(((long)_indicators.Where(x => x.TenantId == tenant).Select(x => x.IndicatorId).Distinct().Count(), _matches.LongCount(x => x.TenantId == tenant))); }
}

public static class ThreatImportParser
{
    public static IReadOnlyList<ThreatIndicatorInput> Parse(string format, string text) => format.ToLowerInvariant() switch { "csv" => Csv(text), "json" => Json(text), "stix" or "stix2" => Stix(text), _ => throw new EnrollmentConflictException("INTEL_IMPORT_FORMAT", "Only CSV, JSON, and the bounded STIX subset are supported.") };
    static List<ThreatIndicatorInput> Csv(string text)
    {
        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n', StringSplitOptions.RemoveEmptyEntries); if (lines.Length < 2) throw new EnrollmentConflictException("INTEL_CSV_INVALID", "CSV header and records are required.");
        var headers = Fields(lines[0]); var typeAt = Array.FindIndex(headers, x => x.Equals("type", StringComparison.OrdinalIgnoreCase)); var valueAt = Array.FindIndex(headers, x => x.Equals("value", StringComparison.OrdinalIgnoreCase)); if (typeAt < 0 || valueAt < 0) throw new EnrollmentConflictException("INTEL_CSV_INVALID", "CSV requires type and value columns.");
        var result = new List<ThreatIndicatorInput>(); foreach (var line in lines.Skip(1)) { var f = Fields(line); if (f.Length != headers.Length || !Enum.TryParse<ThreatIndicatorType>(f[typeAt], true, out var type)) throw new EnrollmentConflictException("INTEL_CSV_INVALID", "CSV record is malformed or has an unsupported type."); result.Add(new(Guid.Empty, type, SafeCell(f[valueAt]), Provenance: "csv")); }
        return result;
    }
    static string[] Fields(string line) { var fields = new List<string>(); var b = new StringBuilder(); var quoted = false; for (var i = 0; i < line.Length; i++) { var ch = line[i]; if (ch == '"') { if (quoted && i + 1 < line.Length && line[i + 1] == '"') { b.Append('"'); i++; } else quoted = !quoted; } else if (ch == ',' && !quoted) { fields.Add(b.ToString()); b.Clear(); } else b.Append(ch); } if (quoted) throw new EnrollmentConflictException("INTEL_CSV_INVALID", "CSV contains an unterminated quote."); fields.Add(b.ToString()); return fields.ToArray(); }
    static string SafeCell(string value) { if (value.Length > 32767 || value.Any(char.IsControl)) throw new EnrollmentConflictException("INTEL_CSV_INVALID", "CSV cell is unsafe."); return value.Length > 0 && "=+-@".Contains(value[0]) ? throw new EnrollmentConflictException("INTEL_CSV_FORMULA", "Formula-prefixed indicator cells are rejected.") : value; }
    static ThreatIndicatorInput[] Json(string text) { using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 16, AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow }); if (doc.RootElement.ValueKind != JsonValueKind.Array) throw new EnrollmentConflictException("INTEL_JSON_INVALID", "JSON import must be an array."); return doc.RootElement.EnumerateArray().Select(x => new ThreatIndicatorInput(Guid.Empty, Enum.Parse<ThreatIndicatorType>(x.GetProperty("type").GetString()!, true), x.GetProperty("value").GetString()!, SourceRecordId: x.TryGetProperty("sourceRecordId", out var id) ? id.GetString() : null, Provenance: "json")).ToArray(); }
    static List<ThreatIndicatorInput> Stix(string text)
    {
        using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 32 }); var root = doc.RootElement; if (root.GetProperty("type").GetString() != "bundle" || root.GetProperty("objects").ValueKind != JsonValueKind.Array) throw new EnrollmentConflictException("INTEL_STIX_INVALID", "STIX import must be a bundle."); var objects = root.GetProperty("objects").EnumerateArray().ToArray(); if (objects.Length > ThreatIntelligenceSafety.MaximumImportRecords) throw new EnrollmentConflictException("INTEL_IMPORT_RECORD_LIMIT", "STIX bundle exceeds record limit.");
        var result = new List<ThreatIndicatorInput>(); foreach (var o in objects) { var kind = o.GetProperty("type").GetString(); if (kind is "malware" or "threat-actor" or "campaign" or "relationship") continue; if (kind != "indicator") continue; var patternType = o.TryGetProperty("pattern_type", out var pt) ? pt.GetString() : "stix"; if (patternType != "stix") throw new EnrollmentConflictException("INTEL_STIX_PATTERN", "Only STIX patterns are supported."); var pattern = o.GetProperty("pattern").GetString() ?? ""; var parsed = ParsePattern(pattern); var validFrom = o.TryGetProperty("valid_from", out var vf) ? vf.GetDateTimeOffset() : (DateTimeOffset?)null; var validUntil = o.TryGetProperty("valid_until", out var vu) ? vu.GetDateTimeOffset() : (DateTimeOffset?)null; result.Add(new(Guid.Empty, parsed.Type, parsed.Value, SourceRecordId: o.GetProperty("id").GetString(), SourceVersion: o.TryGetProperty("modified", out var modified) ? modified.GetString() : null, Confidence: o.TryGetProperty("confidence", out var confidence) ? confidence.GetInt32() : null, ValidFrom: validFrom, ValidUntil: validUntil, Revoked: o.TryGetProperty("revoked", out var revoked) && revoked.GetBoolean(), Tags: o.TryGetProperty("labels", out var labels) ? labels.EnumerateArray().Select(x => x.GetString() ?? "").ToArray() : [], SourceReference: o.TryGetProperty("external_references", out var refs) ? refs.GetRawText() : null, Provenance: "stix2-bounded-subset")); }
        return result;
    }
    static (ThreatIndicatorType Type, string Value) ParsePattern(string pattern) { var map = new Dictionary<string, ThreatIndicatorType>(StringComparer.Ordinal) { ["file:hashes.'SHA-256'"] = ThreatIndicatorType.Sha256, ["file:hashes.'SHA-1'"] = ThreatIndicatorType.Sha1, ["file:hashes.MD5"] = ThreatIndicatorType.Md5, ["domain-name:value"] = ThreatIndicatorType.Domain, ["ipv4-addr:value"] = ThreatIndicatorType.IPv4, ["ipv6-addr:value"] = ThreatIndicatorType.IPv6, ["url:value"] = ThreatIndicatorType.Url }; if (!pattern.StartsWith('[') || !pattern.EndsWith(']')) throw new EnrollmentConflictException("INTEL_STIX_PATTERN", "Unsupported STIX pattern."); var inner = pattern[1..^1]; var at = inner.IndexOf(" = ", StringComparison.Ordinal); if (at < 1 || !map.TryGetValue(inner[..at], out var type)) throw new EnrollmentConflictException("INTEL_STIX_PATTERN", "Unsupported STIX pattern."); var value = inner[(at + 3)..].Trim(); if (value.Length < 2 || value[0] != '\'' || value[^1] != '\'' || value[1..^1].Contains('\'')) throw new EnrollmentConflictException("INTEL_STIX_PATTERN", "Only one exact scalar STIX comparison is supported."); return (type, value[1..^1]); }

    public static IReadOnlyList<ThreatRelationship> Relationships(string tenant, Guid sourceId, string text)
    {
        using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 32 });
        var objects = doc.RootElement.GetProperty("objects").EnumerateArray().ToArray();
        var relationships = new List<ThreatRelationship>();
        foreach (var value in objects.Where(x => x.GetProperty("type").GetString() == "relationship"))
        {
            var source = value.GetProperty("source_ref").GetString() ?? ""; var target = value.GetProperty("target_ref").GetString() ?? ""; var kind = value.GetProperty("relationship_type").GetString() ?? "";
            if (!ValidRef(source) || !ValidRef(target) || source == target || kind.Length is < 1 or > 100 || kind.Any(x => !(char.IsAsciiLetterLower(x) || x == '-'))) throw new EnrollmentConflictException("INTEL_STIX_RELATIONSHIP", "STIX relationship is malformed, recursive, or unsupported.");
            var id = ThreatIntelligenceSafety.StableId(tenant, sourceId.ToString("D"), source, target, kind); relationships.Add(new(id, tenant, sourceId, source, target, kind, value.TryGetProperty("description", out var description) ? description.GetString() : null, "stix2-bounded-subset", DateTimeOffset.UtcNow));
        }
        if (relationships.Count > ThreatIntelligenceSafety.MaximumImportRecords) throw new EnrollmentConflictException("INTEL_STIX_RELATIONSHIP_LIMIT", "STIX relationship count exceeds the bounded limit."); return relationships;
    }
    static bool ValidRef(string value) { var at = value.IndexOf("--", StringComparison.Ordinal); return at is > 0 and < 50 && Guid.TryParse(value[(at + 2)..], out _) && value[..at].All(x => char.IsAsciiLetterLower(x) || x == '-'); }
}
