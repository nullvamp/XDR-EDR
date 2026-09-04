# Analyst information architecture

The prior 77-entry flat navigation is replaced in the visible shell by 23 stable destinations grouped around analyst intent:

| Group | Destinations |
|---|---|
| Monitor | SOC Overview, Alerts, Incidents, Investigations |
| Investigate | Process tree, Entity graph, Attack stories, Hunt, AI Assistant |
| Assets & intelligence | Endpoints, Threat intelligence, Tunnel analytics, Forensics |
| Detection & response | Detections, Detection engineering, Response center, Live Response, Playbooks |
| Operations | Fleet, Updates, Self-protection, Platform health, Administration |

Specialized legacy routes remain directly addressable and server-authorized, but no longer compete in primary navigation. Breadcrumbs retain workspace context. Global search fans out only to bounded tenant APIs and groups authorized endpoints, alerts, incidents, investigations, and indicators by type. Context pivots connect alert, incident, endpoint, process, graph, hunt, response, AI, and DFIR work without duplicating backend logic.

The SOC Overview is an action queue, not a vanity dashboard. Alert and incident details receive local section navigation plus direct process/entity/response/AI pivots. Response, administrative, and rollout workspaces are visually separated because they carry execution or security risk.
