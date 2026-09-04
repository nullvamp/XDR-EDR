# Bounded AI hunt specification

`ai-hunt-proposal.v1` records tenant, analyst, source/prompt hash, normalized intent, the complete `threat-hunt.v1` definition, entity types, predicates, relationships, seven-day window, result/scan/depth limits, estimated cost, evidence citations, provider/model/evidence-package identity and proposal hash.

Pipeline: intent -> safety parsing -> allowlisted structured translation -> existing hunt validation/costing -> mandatory preview -> explicit hash-bound execution. Supported translations are exact path, exact SHA-256, exact DNS name, bounded PowerShell ancestry pivot and persistence entities. Maximum results are 200, maximum scan 5,000, and relationship depth is at most one. Unsupported fields, raw query/search/shell syntax, tenant bypass, activation and response intent fail closed.

Execution revalidates the stored proposal against the tenant authority. Proposal substitution is rejected, and replay of an already executed proposal returns the existing result rather than creating a second run.
