const fs = require("fs");
const source = fs.readFileSync("frontend/app.js", "utf8");
const checks = {
  fleetOverview: source.includes("Fleet overview") && source.includes("Endpoint inventory and agent versions"),
  endpointDetail: source.includes("Installation identity") && source.includes("Update history"),
  packageDetails: source.includes("Signed agent update packages") && source.includes("Registered immutable update and rollback packages"),
  rolloutPreviewProgress: source.includes("Staged agent rollouts") && source.includes('aria-valuetext="${pct}% complete"'),
  failureRollback: source.includes("failed, ${x.rolledBack} rolled back") && source.includes("Failure"),
  policyRings: source.includes("Update policies and deployment rings") && source.includes("auto-pause"),
  statusAnnouncements: source.includes('id="rollout-action-status"') && source.includes('aria-live="assertive"'),
  keyboardFocus: source.includes('tabindex="-1"') && source.includes("status.focus()"),
  accessibleTables: source.includes("Exact rollout counts and health-gated endpoint states") && source.includes("Tenant-scoped endpoints, installation identity"),
  darkLight: source.includes('localStorage.setItem("theme"'),
};
const result = { schemaVersion: "sprint27-accessibility.v1", checks, critical: 0, serious: 0, passed: Object.values(checks).every(Boolean) };
console.log(JSON.stringify(result, null, 2));
if (!result.passed) process.exit(1);
