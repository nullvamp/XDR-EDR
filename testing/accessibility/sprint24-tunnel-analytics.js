const fs = require("fs");
const app = fs.readFileSync("frontend/app.js", "utf8");
const checks = {
  search: app.includes('id="tunnel-search"') && app.includes('role="search"'),
  details: app.includes("Why this finding exists") && app.includes("Exact evidence"),
  chain: app.includes("Bounded multi-tunnel chain"),
  dns: app.includes("DNS") && app.includes("tunnel"),
  exclusions: app.includes('id="tunnel-exclusion"'),
  health: app.includes("tunnelHealthPage"),
  tableAlternative: app.includes("Evidence-backed tunnel chain") && app.includes("<caption>"),
  keyboardFocus: app.includes('tabindex="-1"') && app.includes(".focus()"),
  darkLight: app.includes('localStorage.setItem("theme"')
};
const failures = Object.entries(checks).filter(([, value]) => !value).map(([name]) => name);
console.log(JSON.stringify({ schemaVersion: "sprint24-accessibility.v1", checks, critical: 0, serious: failures.length, passed: failures.length === 0 }, null, 2));
if (failures.length) process.exit(1);
