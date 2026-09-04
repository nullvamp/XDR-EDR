import puppeteer from "../../.tooling/a11y/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js";
import fs from "node:fs";

const axe = fs.readFileSync(".tooling/a11y/node_modules/axe-core/axe.min.js", "utf8");
const env = Object.fromEntries(fs.readFileSync(".env", "utf8").split(/\r?\n/).filter(x => x && !x.startsWith("#") && x.includes("=")).map(x => x.split(/=(.*)/s).slice(0, 2)));
const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || ["C:/Program Files/Google/Chrome/Application/chrome.exe", "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"].find(fs.existsSync);
const browser = await puppeteer.launch({ executablePath, headless: true, args: ["--no-sandbox"] });
const page = await browser.newPage();
await page.goto("http://localhost:8080/#/login", { waitUntil: "networkidle0" });
await page.type('input[name="username"]', env.PLATFORM_BOOTSTRAP_USER);
await page.type('input[name="password"]', env.PLATFORM_BOOTSTRAP_PASSWORD);
await Promise.all([page.click("#login button"), page.waitForNetworkIdle()]);

async function scan(name, hash, theme) {
  await page.evaluate(({ hash, theme }) => { document.documentElement.dataset.theme = theme; location.hash = hash; }, { hash, theme });
  await page.waitForNetworkIdle();
  await page.addScriptTag({ content: axe });
  const result = await page.evaluate(async () => {
    const violations = (await axe.run(document, { resultTypes: ["violations"] })).violations;
    const semantic = [];
    if ([...document.querySelectorAll("input:not([type=hidden]),select,textarea")].some(x => !x.labels?.length && !x.getAttribute("aria-label"))) semantic.push("unlabelled-control");
    if ([...document.querySelectorAll("table")].some(x => !x.querySelector("th"))) semantic.push("table-without-header");
    return { violations, semantic };
  });
  return { name, hash, theme, violations: result.violations.map(x => ({ id: x.id, impact: x.impact, nodes: x.nodes.length })), semanticViolations: result.semantic };
}

const screens = [];
for (const theme of ["dark", "light"]) {
  screens.push(await scan(`services-search-${theme}`, "#/services", theme));
  const serviceDetail = await page.$('a[href^="#/services/"]');
  if (serviceDetail) screens.push(await scan(`service-detail-${theme}`, await serviceDetail.evaluate(x => x.getAttribute("href")), theme));
  screens.push(await scan(`tasks-search-${theme}`, "#/tasks", theme));
  const taskDetail = await page.$('a[href^="#/tasks/"]');
  if (taskDetail) screens.push(await scan(`task-detail-${theme}`, await taskDetail.evaluate(x => x.getAttribute("href")), theme));
  screens.push(await scan(`policy-list-${theme}`, "#/persistence-policies", theme));
  screens.push(await scan(`policy-editor-${theme}`, "#/persistence-policies/new", theme));
}

const blocking = screens.flatMap(x => x.violations).filter(x => ["critical", "serious"].includes(x.impact));
const semantic = screens.flatMap(x => x.semanticViolations);
const report = { schema: "platform.sprint8.persistence-accessibility.v1", executedAt: new Date().toISOString(), authenticated: await page.evaluate(() => Boolean(sessionStorage.getItem("access_token"))), tool: "axe-core 4.10.3", browser: await browser.version(), screens, criticalViolations: blocking.filter(x => x.impact === "critical").length, seriousViolations: blocking.filter(x => x.impact === "serious").length, semanticViolations: semantic.length, passed: blocking.length === 0 && semantic.length === 0 };
fs.writeFileSync("artifacts/sprint8-persistence-accessibility.json", JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
await browser.close();
if (!report.passed) process.exitCode = 1;
