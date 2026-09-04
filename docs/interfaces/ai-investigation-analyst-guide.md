# AI investigation analyst guide

Open **AI investigation** or use **Start read-only analysis** from an alert or incident. Confirm the displayed provider, model and sovereignty mode, select a supported context, create a conversation, and ask a focused question. The history is durable and case-scoped.

Treat the answer as an evidence navigation aid. Check every `[EVID-NNNN]` by opening it in the evidence drawer; verify source, timestamp, endpoint/entity, provenance and fields. `Observed` is direct package evidence, `Derived` is deterministic platform computation, `Inference` is interpretation, `Ambiguous` preserves source conflict/quality, and `Unknown` means the package cannot answer. Confidence is categorical, not a probability. A truncation notice means the answer is incomplete.

Recommended pivots and response suggestions are advisory. The assistant cannot run shell/Live Response, retrieve arbitrary tenant data, create response actions, start playbooks, activate rules or browse the internet. Use established workflows and approvals yourself. AI-generated notes remain labeled drafts until **Accept note** is explicitly invoked; acceptance is audited under your identity. If AI is degraded, continue normal timeline, hunt, graph, incident, forensic and response work—the underlying platform remains available.
