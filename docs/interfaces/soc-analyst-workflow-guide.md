# SOC analyst workflow guide

Start in **SOC Overview**. Open a critical/high or new item from the priority queue, then use the alert header to distinguish severity, priority, state, assignment, and evidence. Evidence and audit section tabs keep the current object; process, entity, response, and AI tabs are explicit context pivots.

For incident work, open the linked incident and keep the incident as the case context while pivoting through its alert set, timeline, attack story, entity graph, process tree, Hunt, DFIR investigation, response, and AI assistant. Evidence remains authoritative. AI output is advisory, marked with provider/model/policy/citations, and must lead back to the cited object.

Use global search for a bounded hostname, process, hash, file, domain, IP, user, alert, incident, investigation, or IOC value. Use saved views for bounded alert, incident, hunt, or fleet filters. Saved views belong to the signed-in subject and do not contain raw query language.

Response actions are separate from ordinary triage. Verify exact endpoint/entity, stable native identity, expected effect, reversibility, approval state, and current target state. Destructive actions require their established confirmation and server-side approval. If a mutation fails with an uncertain result, inspect the action audit and target state before retrying.

The activity drawer links only operational work: approvals, response actions, forensic collections, and rollouts. Optional AI, search, or object-storage degradation does not prevent authoritative triage where the underlying canonical service remains available.

## Sprint 36 refined flow

Opening an alert from a filtered queue now retains the exact queue URL, loaded-page position and scroll position. Use **Previous alert** and **Next alert** for repetitive triage, then **Back to filtered queue** to return without restarting at the top. The full alert route remains deep-linkable; no duplicate split-view authority was introduced.

Incident detail begins with a bounded strongest-evidence summary and carries the incident identity into attack-story, graph, DFIR, response and AI pivots. The centralized **Approvals** view is a read-only priority overview for response, playbook and forensic gates; approve or deny only in the linked authoritative detail workflow. Other governed changes stay in Maintenance, Detection, Administration and Update workspaces.

Sensitive endpoint, response, approval, self-protection, rollout, forensic and Live Response pages show when state was refreshed. Refresh before acting on an old target. Rapid navigation cancels obsolete reads, but never silently cancels, retries or replays a mutation.

Quick navigation ranks up to five recent safe workspaces. Saved views and recent routes are scoped to both tenant and signed-in subject. Process-tree analysts may keyboard-focus a node, choose **Focus selected subtree**, and use **Reset view** to restore the bounded loaded tree.
