const fs = require("fs");
const path = require("path");
const root = path.resolve(__dirname, "../..");
const { launch } = require(path.join(root, ".tooling/a11y/node_modules/puppeteer-core"));
const axeSource = fs.readFileSync(path.join(root, ".tooling/a11y/node_modules/axe-core/axe.min.js"), "utf8");
const env = Object.fromEntries(fs.readFileSync(path.join(root, ".env"), "utf8").split(/\r?\n/).filter(x => /^[^#][^=]*=/.test(x)).map(x => { const i=x.indexOf("="); return [x.slice(0,i),x.slice(i+1)]; }));
(async () => {
  const browser = await launch({ headless: true, executablePath: "C:/Program Files/Google/Chrome/Application/chrome.exe" });
  const page = await browser.newPage();
  await page.goto("http://localhost:8080", { waitUntil: "networkidle0" });
  const token = await page.evaluate(async credentials => {
    const response = await fetch("/api/v1/auth/token", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(credentials) });
    return (await response.json()).access_token;
  }, { username: env.PLATFORM_BOOTSTRAP_USER, password: env.PLATFORM_BOOTSTRAP_PASSWORD });
  await page.evaluate(value => sessionStorage.setItem("access_token", value), token);
  const eventId = await page.evaluate(async value => {
    const response = await fetch("/api/v1/persistence-configurations?pageSize=1", { headers: { Authorization: `Bearer ${value}` } });
    return (await response.json()).data.items[0].eventId;
  }, token);
  const screens = [];
  for (const theme of ["dark", "light"]) {
    await page.evaluate(value => localStorage.setItem("theme", value), theme);
    for (const [name, hash] of [["configuration-search", "#/persistence-configurations"], ["configuration-detail", `#/persistence-configurations/${eventId}`], ["wmi-subscriptions", "#/wmi-subscriptions"], ["policy-list", "#/persistence-policies"], ["policy-editor", "#/persistence-policies/new"]]) {
      await page.goto(`http://localhost:8080/${hash}`, { waitUntil: "networkidle0" });
      await page.addScriptTag({ content: axeSource });
      const result = await page.evaluate(async () => {
        const axe = await window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa"] } });
        const semantic = [];
        if (!document.querySelector("main") || !document.querySelector("h1") || !document.querySelector("#content")) semantic.push("landmark-or-heading-missing");
        if (!document.querySelector(".skip")) semantic.push("skip-link-missing");
        return { violations: axe.violations.map(v => ({ id:v.id, impact:v.impact, nodes:v.nodes.length })), semanticViolations: semantic };
      });
      screens.push({ name:`${name}-${theme}`, hash, theme, ...result });
    }
  }
  const serious = screens.flatMap(x => x.violations).filter(x => x.impact === "critical" || x.impact === "serious");
  const report = { schema:"platform.sprint9.persistence-accessibility.v1", executedAt:new Date().toISOString(), authenticated:true, tool:`axe-core ${require(path.join(root,".tooling/a11y/node_modules/axe-core/package.json")).version}`, browser:await browser.version(), screens, criticalOrSeriousViolations:serious.length, semanticViolations:screens.flatMap(x=>x.semanticViolations).length, passed:serious.length===0 && screens.every(x=>x.semanticViolations.length===0) };
  await browser.close();
  fs.writeFileSync(path.join(root,"artifacts/sprint9-persistence-accessibility.json"),JSON.stringify(report,null,2));
  process.stdout.write(JSON.stringify(report,null,2));
  process.exitCode = report.passed ? 0 : 1;
})().catch(error => { console.error(error.message); process.exitCode=1; });
