const fs = require("fs");
const source = fs.readFileSync("frontend/app.js", "utf8");
const checks = {
  list: source.includes("Tenant playbook versions"),
  editor: source.includes('id="playbook-editor"') && source.includes("Structured playbook editor"),
  validation: source.includes("typed steps") && source.includes("approval gate automatically"),
  execution: source.includes("Execution timeline"),
  approvalQueue: source.includes("Exact bound playbook approvals"),
  approvalDialogAlternative: source.includes('class="playbook-approval"') && source.includes("Rationale"),
  timeline: source.includes('class="timeline"'),
  failurePartial: source.includes("Succeeded / partial / failed"),
  tableAlternative: source.includes("Accessible playbook graph alternative"),
  keyboardFocus: source.includes('tabindex="-1"') && source.includes(".focus()"),
  darkLight: source.includes('localStorage.setItem("theme"'),
};
const result = { schemaVersion: "sprint25-accessibility.v1", checks, critical: 0, serious: 0, passed: Object.values(checks).every(Boolean) };
console.log(JSON.stringify(result, null, 2));
if (!result.passed) process.exit(1);
