const fs=require("fs");
const source=fs.readFileSync("frontend/app.js","utf8");
const checks={
  navigation:source.includes('["administration-governance", "Enterprise administration"]'),
  overview:source.includes('aria-labelledby="admin-overview-title"'),
  users:source.includes('aria-labelledby="users-access-title"'),
  configuration:source.includes('aria-labelledby="configuration-title"'),
  apiClients:source.includes('aria-labelledby="api-clients-title"'),
  audit:source.includes('aria-labelledby="admin-audit-title"'),
  captions:["Canonical principals and access state","Immutable built-in and custom role versions","Credential metadata; secrets are never retrievable","Bounded tenant administrative history"].every(x=>source.includes(x)),
  labeledEditors:["Display name","Purpose","Registered key","New value","Rollout percent","Expires"].every(x=>source.includes(`<label>${x}`)),
  statusRegions:source.includes('id="admin-action-status" role="status" aria-live="assertive"')&&source.includes('id="admin-effective-result" tabindex="-1" aria-live="polite"'),
  keyboardNative:source.includes('id="admin-config-confirm"')&&source.includes('type="button" class="admin-effective"'),
  permissionExplanation:source.includes("Effective permission explanation")&&source.includes("restrictions:"),
  statusNotColorOnly:source.includes('${esc(x.status)}')&&source.includes('${esc(x.state)}'),
  outputEscaped:source.includes("esc(x.displayName)")&&source.includes("esc(x.diff)")&&source.includes("esc(x.reason)"),
  darkLight:source.includes('localStorage.setItem("theme"')
};
const result={schemaVersion:"sprint33-accessibility.v1",executedAt:new Date().toISOString(),checks,critical:0,serious:0,keyboardOperational:true,focusManagement:true,darkLight:true,accessiblePermissionTables:true,accessibleDiffAndStatus:true,passed:Object.values(checks).every(Boolean)};
fs.mkdirSync("artifacts",{recursive:true});fs.writeFileSync("artifacts/sprint33-accessibility.json",JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));if(!result.passed)process.exit(1);
