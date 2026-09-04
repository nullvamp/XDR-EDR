const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../..");
const { launch } = require(path.join(root, ".tooling/a11y/node_modules/puppeteer-core"));
const axeSource = fs.readFileSync(path.join(root, ".tooling/a11y/node_modules/axe-core/axe.min.js"), "utf8");
const env = Object.fromEntries(fs.readFileSync(path.join(root, ".env"), "utf8").split(/\r?\n/).filter((line) => /^[^#][^=]*=/.test(line)).map((line) => {
  const index = line.indexOf("=");
  return [line.slice(0, index), line.slice(index + 1).replace(/^['"]|['"]$/g, "")];
}));
const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || [
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/BraveSoftware/Brave-Browser/Application/brave.exe",
].find(fs.existsSync);

(async () => {
  const browser = await launch({ headless: true, executablePath, args: ["--no-sandbox"] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1600, height: 1100 });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("http://127.0.0.1:8080", { waitUntil: "domcontentloaded", timeout: 30000 });
  const token = await page.evaluate(async (credentials) => (await (await fetch("/api/v1/auth/token", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(credentials) })).json()).access_token, { username: env.PLATFORM_BOOTSTRAP_USER, password: env.PLATFORM_BOOTSTRAP_PASSWORD });
  await page.evaluate((value) => sessionStorage.setItem("access_token", value), token);
  const inventory = await page.evaluate(async () => {
    const headers = { Authorization: `Bearer ${sessionStorage.getItem("access_token")}` };
    const response = await fetch("/api/v1/triage-queue?sort=updated-desc", { headers: { Authorization: `Bearer ${sessionStorage.getItem("access_token")}` } });
    const items = (await response.json()).data.items || [];
    const alertId = items.find((item) => item.title === "PowerShell retrieval and execution semantics")?.alertId || items.find((item) => !item.title.startsWith("Sprint 12 starter"))?.alertId || items[0]?.alertId;
    const evidence = alertId ? (await (await fetch(`/api/v1/alerts/${alertId}/evidence`, { headers })).json()).data : null;
    const pivots = alertId ? (await (await fetch(`/api/v1/alerts/${alertId}/pivots`, { headers })).json()).data : null;
    return { alertId, processEntityId: evidence?.processEntities?.[0], endpointId: pivots?.endpoint?.split("/").pop() };
  });
  const { alertId, processEntityId, endpointId } = inventory;
  if (!alertId) throw Error("A populated alert is required for the SOC V2 validation.");
  const output = path.join(root, "artifacts/ui-redesign");
  fs.mkdirSync(output, { recursive: true });
  const views = [
    ["alerts", "#/alerts", "#alert-filter"],
    ["alert-detail", `#/alerts/${alertId}`, ".alert-v2"],
    ["process-search", "#/processes", "table"],
    ["process-tree-default", "#/process-tree", ".process-map-shell"],
    ["process-tree", processEntityId && endpointId ? `#/process-tree?root=${encodeURIComponent(processEntityId)}&endpointId=${encodeURIComponent(endpointId)}` : "#/process-tree", "#content"],
    ["process-tree-stale", "#/process-tree?root=stale-process-identity", ".process-context-picker"],
    ["entity-graph-default", "#/entity-graph", ".entity-map-shell"],
    ["entity-graph", processEntityId && endpointId ? `#/entity-graph?root=${encodeURIComponent(processEntityId)}&endpointId=${encodeURIComponent(endpointId)}` : "#/entity-graph", ".entity-map-shell"],
    ["hunting", "#/threat-hunting", ".hunt-workbench"],
    ["forensics", "#/forensic-collections", "#content"],
    ["response", "#/response-actions", "#content"],
    ["administration", "#/administration-governance", "#content"],
  ];
  const results = [];
  for (const [name, hash, selector] of views) {
    await page.goto(`http://127.0.0.1:8080/${hash}`, { waitUntil: "domcontentloaded", timeout: 30000 });
    await page.waitForSelector(selector, { timeout: 30000 });
    await page.waitForFunction(() => { const content = document.querySelector("#content"); return content && !content.querySelector(".skeleton") && content.innerText.trim().length > 20; }, { timeout: 60000 });
    if (name === "process-tree") await page.click(".process-map-node.selected");
    await page.evaluate(axeSource);
    const result = await page.evaluate(async (view) => {
      const axe = await window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa"] } });
      return {
        view,
        criticalOrSerious: axe.violations.filter((violation) => ["critical", "serious"].includes(violation.impact)).map((violation) => ({ id: violation.id, nodes: violation.nodes.length })),
        horizontalOverflow: document.documentElement.scrollWidth > innerWidth + 2,
        unlabeledControls: [...document.querySelectorAll("input:not([type=hidden]),textarea,select")].filter((control) => !control.labels?.length && !control.getAttribute("aria-label")).length,
        tablesWithoutCaptions: [...document.querySelectorAll("table")].filter((table) => !table.caption).length,
        domNodes: document.querySelectorAll("*").length,
      };
    }, name);
    if (name === "alert-detail") Object.assign(result, await page.evaluate(() => ({
      commandVisible: !!document.querySelector(".command-line") && document.querySelector(".command-line").innerText.trim().length > 12,
      processMapVisible: !!document.querySelector(".process-map-shell"),
      decisionSummaryVisible: !!document.querySelector(".why-fired"),
      processTreeLinkCarriesEndpoint: document.querySelector('a[href^="#/process-tree?root="]')?.getAttribute("href").includes("endpointId=") || false,
      processMapNodes: document.querySelectorAll(".process-map-node").length,
    })));
    if (name === "process-search") Object.assign(result, await page.evaluate(() => ({
      namedProcessRows: [...document.querySelectorAll("tbody tr")].filter((row) => row.querySelector("td:nth-child(2) strong")?.textContent.trim()).length,
      lineageLinks: document.querySelectorAll('a[href^="#/process-tree?root="]').length,
    })));
    if (name === "process-tree") Object.assign(result, await page.evaluate(() => ({
      lineageNodes: document.querySelectorAll(".process-map-node").length,
      selectedProcessNamed: !document.querySelector(".process-map-node.selected")?.textContent.includes("Unknown process"),
      inspectorCommandVisible: (document.querySelector(".process-node-inspector")?.textContent || "").includes("Command line"),
    })));
    await page.screenshot({ path: path.join(output, `${name}.png`), fullPage: name !== "alert-detail" });
    results.push(result);
  }
  const report = { schemaVersion: "soc-v2-workspaces.v1", executedAt: new Date().toISOString(), alertId, results, javascriptErrors: [...new Set(errors)] };
  report.passed = !report.javascriptErrors.length && results.every((result) => !result.criticalOrSerious.length && !result.horizontalOverflow && !result.unlabeledControls && !result.tablesWithoutCaptions && (result.view !== "alert-detail" || (result.commandVisible && result.processMapVisible && result.processMapNodes >= 2 && result.decisionSummaryVisible && result.processTreeLinkCarriesEndpoint)) && (result.view !== "process-search" || (result.namedProcessRows > 0 && result.lineageLinks > 0)) && (result.view !== "process-tree" || (result.lineageNodes >= 2 && result.selectedProcessNamed && result.inspectorCommandVisible)));
  fs.writeFileSync(path.join(output, "validation.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
  await browser.close();
  if (!report.passed) process.exitCode = 1;
})().catch((error) => { console.error(error); process.exit(1); });
