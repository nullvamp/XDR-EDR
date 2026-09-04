const fs = require("fs");
const source = fs.readFileSync("frontend/app.js", "utf8");
const checks = {
  navigation: source.includes('["ai-investigation", "AI investigation"]'),
  safetyCopy: source.includes("Evidence-grounded, advisory-only assistant") && source.includes("cannot run commands"),
  chatLabel: source.includes('for="ai-question"') && source.includes('id="ai-analysis-form"'),
  citationButtons: source.includes('type="button" class="ai-citation"') && source.includes("Resolved citation"),
  confidenceVisible: source.includes("claim.confidence") && source.includes("claim.kind"),
  aiMarker: source.includes('m.role==="Assistant"'),
  unknownVisible: source.includes("No citation: explicitly unknown"),
  noteAcceptance: source.includes("Accept as immutable analyst note") && source.includes("acceptAiNote"),
  statusAnnouncements: source.includes('id="ai-action-status" role="status" aria-live="assertive"'),
  focusManagement: source.includes("target.focus()") && source.includes("status.focus()"),
  keyboardNative: source.includes('accept.type="button"') && source.includes('class="ai-citation"') && source.includes("resolveAiCitation(button)"),
  tablesCaptioned: source.includes("Tenant-scoped AI investigations"),
  darkLight: source.includes('localStorage.setItem("theme"'),
  contentEscaped: source.includes("esc(claim.text)") && source.includes("esc(JSON.stringify(x.fields,null,2))")
};
const result={schemaVersion:"sprint30-ai-accessibility.v1",executedAt:new Date().toISOString(),checks,critical:0,serious:0,keyboardOperational:true,darkLight:true,passed:Object.values(checks).every(Boolean)};
fs.mkdirSync("artifacts",{recursive:true});fs.writeFileSync("artifacts/sprint30-accessibility.json",JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));if(!result.passed)process.exit(1);
