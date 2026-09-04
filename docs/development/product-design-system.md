# Product design system

Sprint 35 establishes one semantic UI vocabulary for the SOC, investigation, response, forensics, fleet, and administration surfaces. `frontend/design-system.css` is the authority for product tokens and shared component behavior; existing narrow stylesheets remain compatibility layers.

## Foundations

- Typography uses `--text-xs` through `--text-2xl`; spacing uses `--space-1` through `--space-8`.
- Surfaces, text, borders, focus, elevation, radius, severity, priority, execution, evidence, and operational state use semantic variables. Dark and light themes bind the same semantics.
- Desktop is primary. The 1180 px and 760 px breakpoints collapse the shell, toolbars, cards, and split workspaces without hiding data.
- Focus is always visible. Motion respects `prefers-reduced-motion`.

## Shared patterns

The shell, grouped navigation, breadcrumbs, global search, activity drawer, command dialog, toasts, workspace tabs, action strips, metrics, panels, tables, filters, forms, badges, banners, loading skeletons, empty/error/degraded states, bounded tree/graph viewports, and entity drawer share the same tokens. Tables provide a caption, keyboard-sortable loaded-page headers, row focus, and compact/comfortable density.

Severity describes technical consequence; priority describes workflow order. Operational, workflow, execution, and evidence states retain text labels and never rely on color alone. Investigative actions use ordinary controls. Destructive or security-impacting actions use the danger/risk treatment and still pass through server authorization, preview, confirmation, approval, and audit.

## Safety rules

The client escapes untrusted text before HTML insertion, accepts bounded filter/search state, stores only user-scoped allow-listed saved-view filters, and never constructs raw database/search queries. The server remains authoritative for tenant scope, permission, target identity, approval, and execution state. Optional subsystem failure is shown as degraded or unavailable; it does not turn the entire platform green or fabricate data.

## SOC V2 evidence-first layer

`frontend/soc-v2.css` refines this foundation with a restrained, compact operational shell and an evidence-first hierarchy. Alerts show their decision summary, exact command/execution evidence, and connected process map before provenance and lifecycle controls. Process and entity relationships use dedicated node maps with exact accessible table alternatives. Hunt DSL, technical identifiers, raw provenance, and long audit trails use progressive disclosure; they remain available without competing with initial triage information. Shared workspace introductions, progressive filters, semantic table states, and wide-grid behavior apply consistently across investigation, forensics, response, detection, operations, and administration surfaces.
