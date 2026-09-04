# AI-assisted ATT&CK coverage methodology

Coverage authority is the tenant's verified ATT&CK inventory plus canonical telemetry, production rule/correlation versions, active state, successful fixtures and last validation. A rule name alone contributes no coverage.

States are deterministic:

- `Covered`: telemetry available, detection implemented/tested and production active.
- `PartiallyCovered`: implemented and tested, but not production active or otherwise limited.
- `TelemetryAvailableNoDetection`: telemetry exists with no implemented detection.
- `TelemetryInsufficient`: relevant telemetry exists but required semantics/fields are incomplete.
- `NotObservableBySource`: the platform source cannot observe the required semantics.
- `NotValidated`: implementation exists without successful validation.

Every row exposes tactic, verified technique/sub-technique, rule/correlation IDs, telemetry sources, required fields, fixtures, limitations, last validation and the source facts used to derive its state. AI suggestions cannot change production mappings without explicit review.
