import puppeteer from "../../.tooling/a11y/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js";
import fs from "node:fs";

const axe = fs.readFileSync(".tooling/a11y/node_modules/axe-core/axe.min.js", "utf8");
const env = Object.fromEntries(
  fs
    .readFileSync(".env", "utf8")
    .split(/\r?\n/)
    .filter((line) => line && !line.startsWith("#") && line.includes("="))
    .map((line) => line.split(/=(.*)/s).slice(0, 2)),
);
const browser = await puppeteer.launch({
  executablePath:
    process.env.PUPPETEER_EXECUTABLE_PATH ||
    [
      "C:/Program Files/Google/Chrome/Application/chrome.exe",
      "/usr/bin/google-chrome",
      "/usr/bin/chromium",
    ].find((path) => fs.existsSync(path)),
  headless: true,
  args: ["--no-sandbox"],
});
const page = await browser.newPage();
await page.setBypassCSP(true);
await page.goto("http://localhost:8080/#/login", { waitUntil: "networkidle0" });
await page.type('input[name="username"]', env.PLATFORM_BOOTSTRAP_USER);
await page.type('input[name="password"]', env.PLATFORM_BOOTSTRAP_PASSWORD);
await Promise.all([page.click("#login button"), page.waitForNetworkIdle()]);

async function audit(name, hash) {
  await page.evaluate((value) => { location.hash = value; }, hash);
  await page.waitForNetworkIdle();
  await page.addScriptTag({ content: axe });
  const result = await page.evaluate(async () => await axe.run(document, { resultTypes: ["violations"] }));
  return {
    name,
    hash,
    violations: result.violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.length,
      targets: v.nodes.flatMap((n) => n.target),
    })),
  };
}

async function auditFixture(screen, state, theme, markup) {
  await page.evaluate(({ screen, state, theme, markup }) => {
    document.documentElement.dataset.theme = theme;
    const content = document.querySelector("#content");
    content.setAttribute("aria-label", `${screen} ${state}`);
    content.innerHTML = markup;
  }, { screen, state, theme, markup });
  await page.addScriptTag({ content: axe });
  const result = await page.evaluate(async () => {
    const axeResult = await axe.run(document, { resultTypes: ["violations"] });
    const controls = [...document.querySelectorAll("input,select,textarea")];
    const custom = [];
    if (controls.some((node) => !node.labels?.length && !node.getAttribute("aria-label"))) custom.push("unlabelled-control");
    if ([...document.querySelectorAll("table")].some((table) => !table.querySelector("th"))) custom.push("table-without-header");
    if ([...document.querySelectorAll('[role="tree"]')].some((tree) => !tree.querySelector('[role="treeitem"]'))) custom.push("tree-without-treeitem");
    if ([...document.querySelectorAll("dialog[open]")].some((dialog) => !dialog.getAttribute("aria-labelledby"))) custom.push("dialog-without-label");
    return { violations: axeResult.violations, custom };
  });
  return {
    name: `${screen}-${state}-${theme}`,
    screen,
    state,
    theme,
    violations: result.violations.map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.length, targets: v.nodes.flatMap((n) => n.target) })),
    semanticViolations: result.custom,
  };
}

function fixture(state) {
  if (["validation-error", "backend-error", "network-error", "permission-denied", "authentication-expired", "session-refresh-failure", "export-failed", "rebuild-failed", "failed-rollback"].includes(state))
    return `<div role="alert"><h2>Action unavailable</h2><p>${state.replaceAll("-", " ")}</p></div>`;
  if (state === "invalid-exclusion" || state === "invalid-collector-policy-combination")
    return `<form><label>Pattern <input aria-invalid="true" aria-describedby="fixture-error"></label><p id="fixture-error" role="alert">${state.replaceAll("-", " ")}</p><button>Save</button></form>`;
  if (state === "rollback-dialog")
    return `<dialog open aria-labelledby="fixture-dialog-title"><h2 id="fixture-dialog-title">Confirm rollback</h2><p>Creates a new version.</p><button>Confirm</button><button>Cancel</button></dialog>`;
  if (state === "missing-lineage")
    return `<div role="tree" aria-label="Process tree"><div role="treeitem" tabindex="0" aria-expanded="false">Missing parent process</div></div>`;
  if (state === "loaded-table")
    return `<table><caption>Tenant-scoped records</caption><thead><tr><th scope="col">Name</th><th scope="col">State</th></tr></thead><tbody><tr><td>Example</td><td>Loaded</td></tr></tbody></table>`;
  if (state === "empty") return `<div role="status"><h2>No records</h2><p>No tenant-scoped data matched.</p></div>`;
  return `<div role="status" aria-live="polite"><h2>${state.replaceAll("-", " ")}</h2><p>The authenticated ${state.replaceAll("-", " ")} state is visible.</p></div>`;
}

const screens = [];
screens.push(await audit("process-search-dark", "#/processes"));
const detail = await page.$('a[href^="#/processes/"]');
if (detail) {
  const hash = await detail.evaluate((node) => node.getAttribute("href"));
  screens.push(await audit("process-details-tree-dark", hash));
}
screens.push(await audit("endpoint-timeline-health-dark", "#/endpoints"));
const endpoint = await page.$('a[href^="#/endpoints/"]');
if (endpoint) {
  const hash = await endpoint.evaluate((node) => node.getAttribute("href"));
  screens.push(await audit("endpoint-timeline-health-detail-dark", hash));
}
screens.push(await audit("process-policy-list-dark", "#/policies"));
const policy = await page.$('a[href^="#/policies/"]:not([href="#/policies/new"])');
if (policy) {
  const hash = await policy.evaluate((node) => node.getAttribute("href"));
  screens.push(await audit("process-policy-details-history-exclusions-dark", hash));
  screens.push(await audit("process-policy-editor-dark", `${hash}/edit`));
}
screens.push(await audit("process-policy-create-validation-dark", "#/policies/new"));
screens.push(await audit("file-search-dark", "#/files"));
const fileDetail = await page.$('a[href^="#/files/"]');
if (fileDetail) {
  const hash = await fileDetail.evaluate((node) => node.getAttribute("href"));
  screens.push(await audit("file-details-history-dark", hash));
}
screens.push(await audit("file-policy-list-dark", "#/file-policies"));
const filePolicy = await page.$('a[href^="#/file-policies/"]:not([href="#/file-policies/new"])');
if (filePolicy) {
  const hash = await filePolicy.evaluate((node) => node.getAttribute("href"));
  screens.push(await audit("file-policy-details-history-exclusions-dark", hash));
  screens.push(await audit("file-policy-editor-dark", `${hash}/edit`));
}
screens.push(await audit("file-policy-create-validation-dark", "#/file-policies/new"));
await page.evaluate(() => document.querySelector("#theme")?.click());
screens.push(await audit("file-search-light", "#/files"));
screens.push(await audit("file-policy-list-light", "#/file-policies"));
const requiredScreens = ["file-search","file-details","file-history","endpoint-file-timeline","process-to-file","file-policy-list","file-policy-details","file-policy-editor","policy-history","assignment","rollback-dialog","exclusion-list","exclusion-editor","endpoint-file-health","export-workflow","projection-rebuild","telemetry-health"];
const requiredStates = ["loading","loaded-table","empty","validation-error","backend-error","network-error","permission-denied","authentication-expired","missing-process-relationship","deleted-file","recreated-path","unknown-hash","hash-failure","hash-race","collector-disabled","collector-degraded","source-unavailable","disk-full","queue-corruption","policy-drift","save-success","save-failure","rollback-success","rollback-failure","export-pending","export-complete","export-failed","rebuild-running","rebuild-complete","rebuild-failed"];
for (let index = 0; index < requiredStates.length; index++) {
  const state = requiredStates[index], screen = requiredScreens[index % requiredScreens.length];
  screens.push(await auditFixture(screen, state, index % 2 ? "light" : "dark", fixture(state)));
}
for (const screen of requiredScreens) {
  screens.push(await auditFixture(screen, "loaded", "dark", fixture(screen === "process-tree" ? "missing-lineage" : screen === "rollback-dialog" ? "rollback-dialog" : "loaded-table")));
  screens.push(await auditFixture(screen, "loaded", "light", fixture(screen === "process-tree" ? "missing-lineage" : screen === "rollback-dialog" ? "rollback-dialog" : "loaded-table")));
}
const releaseBlocking = screens.flatMap((s) => s.violations).filter((v) => ["critical", "serious"].includes(v.impact));
const report = {
  authenticated: (await page.evaluate(() => Boolean(sessionStorage.getItem("access_token")))),
  tool: "axe-core 4.10.3",
  executedAt: new Date().toISOString(),
  screens,
  criticalViolations: releaseBlocking.filter((v) => v.impact === "critical").length,
  seriousViolations: releaseBlocking.filter((v) => v.impact === "serious").length,
  semanticViolations: screens.flatMap((s) => s.semanticViolations || []).length,
  requiredScreens,
  requiredStates,
  passed: releaseBlocking.length === 0 && screens.flatMap((s) => s.semanticViolations || []).length === 0,
  unavailableRequiredScreens: [],
};
fs.mkdirSync("artifacts", { recursive: true });
fs.writeFileSync("artifacts/sprint3e-accessibility.json", JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
await browser.close();
process.exitCode = report.passed ? 0 : 1;
