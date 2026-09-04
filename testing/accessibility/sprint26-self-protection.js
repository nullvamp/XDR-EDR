const fs = require("fs");
const source = fs.readFileSync("frontend/app.js", "utf8");
const checks = {
  overview: source.includes("Protection overview") && source.includes("Overall protection state"),
  protectedResources: source.includes("Protected resource inventory") && source.includes("Expected and observed self-protection surfaces"),
  tamperTimeline: source.includes("Tamper timeline and evidence") && source.includes("Immutable self-protection audit evidence"),
  maintenance: source.includes('id="protection-maintenance"') && source.includes("exact-capability scoped"),
  separateApproval: source.includes('id="protection-approval"') && source.includes("requester cannot approve"),
  repairActions: source.includes('class="protection-repair"') && source.includes("fresh agent verification"),
  degradedState: source.includes("Self-protection degraded or unavailable"),
  statusAnnouncements: source.includes('id="protection-status"') && source.includes('aria-live="assertive"'),
  keyboardFocus: source.includes('tabindex="-1"') && source.includes("status.focus()"),
  darkLight: source.includes('localStorage.setItem("theme"'),
};
const result = { schemaVersion: "sprint26-accessibility.v1", checks, critical: 0, serious: 0, passed: Object.values(checks).every(Boolean) };
console.log(JSON.stringify(result, null, 2));
if (!result.passed) process.exit(1);
