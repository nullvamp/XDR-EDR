# AI hunting and detection-engineer guide

Open **Detection engineering**. Enter a supported hunt intent, inspect its structured predicates, scope, cost, limits, explanation, likely misses and false positives, then use **Execute reviewed bounded hunt**. Nothing runs while building the preview.

For content, create a detection or correlation draft using existing domains, fields, operators, stable joins and a verified ATT&CK technique. Review the component scorecard and eight-case fixture matrix. Use bounded historical simulation, request advisory tuning, compare against a current repository version, and inspect AI explanations grounded in the authoritative rule.

**Save as inactive repository draft** records the exact proposal hash and analyst decision; it never activates the rule. Exclusion, threshold, severity, mapping and promotion remain separate human decisions through existing lifecycle controls. Treat frequency as a tuning lead, never proof of benignness. Rejected/unsupported ideas should remain rejected rather than being rewritten as raw SQL, search DSL, regex, shell or code.
