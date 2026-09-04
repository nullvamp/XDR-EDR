# SOC V2 evidence-first interface

The SOC V2 redesign replaces backend-object-first presentation with an analyst decision hierarchy while preserving existing API, authorization, approval, and audit contracts.

## Product rules

1. Explain what happened and why it matters before showing identifiers.
2. Put exact observed evidence—especially process path and full command line—above technical provenance.
3. Distinguish observation, interpretation, ambiguity, and missing telemetry in text as well as color.
4. Keep common filters visible and move infrequent fields behind an explicit progressive-filter control.
5. Preserve deep technical access through expandable details instead of forcing it into the initial view.
6. Separate investigation controls from security-impacting response controls.
7. Use purpose-built visualizations only when relationships or sequence materially benefit from them.

## Specialized workspaces

- Alert detail: decision summary, exact command/execution context, inline process map, investigation pivots, triage forms, and collapsed provenance/audit.
- Process tree: connected evidence-backed process nodes, selected-root state, pan/scroll viewport, zoom/fit controls, and an exact relationship-table alternative.
- Entity graph: node topology with solid versus ambiguous edges, type encoding, selected root, zoom/fit controls, and exact accessible entity/relationship tables.
- Threat hunting: readable question and bounded execution plan first; raw DSL is an advanced editor.
- Forensics: scope, lifecycle, evidence integrity, retention, and custody retain distinct hierarchy and semantic state treatments.
- Response and approvals: exact target and risk context remain visually separated from investigation; server authorization and confirmation are unchanged.
- Detection, fleet, resilience, and administration: shared workspace orientation, semantic states, progressive filters, compact data grids, and explicit security-impact banners.

## Implementation

- `frontend/soc-v2.css` is loaded after compatibility styles and contains the evidence-first visual layer.
- `frontend/app.js` owns safe rendering and progressive enhancement. It uses native endpoint process-tree evidence when an alert-originated process is not present in the investigation projection.
- `backend/Platform.ServiceHost/Program.cs` explicitly serves the new static stylesheet.
- `testing/accessibility/soc-v2-workspaces.js` validates populated primary workspaces, alert evidence visibility, process-map presence, accessibility, captions, labels, overflow, and JavaScript errors.

No response action, collection, hunt, or policy mutation is made automatically by this redesign.
