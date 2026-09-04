const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname, '../..');
const { launch } = require(path.join(root, '.tooling/a11y/node_modules/puppeteer-core'));
const axeSource = fs.readFileSync(path.join(root, '.tooling/a11y/node_modules/axe-core/axe.min.js'), 'utf8');
const env = Object.fromEntries(fs.readFileSync(path.join(root, '.env'), 'utf8').split(/\r?\n/).filter(x => /^[^#][^=]*=/.test(x)).map(x => { const i = x.indexOf('='); return [x.slice(0, i), x.slice(i + 1)]; }));
const report = JSON.parse(fs.readFileSync(path.join(root, 'artifacts/sprint34-dfir-profiles.json'), 'utf8').replace(/^\uFEFF/, ''));
(async () => {
  const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || ['C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'].find(fs.existsSync);
  const browser = await launch({ headless: true, executablePath, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  await page.goto('http://127.0.0.1:8080', { waitUntil: 'networkidle0' });
  const token = await page.evaluate(async credentials => (await (await fetch('/api/v1/auth/token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(credentials) })).json()).access_token, { username: env.PLATFORM_BOOTSTRAP_USER, password: env.PLATFORM_BOOTSTRAP_PASSWORD });
  await page.evaluate(value => sessionStorage.setItem('access_token', value), token);
  const evidenceId = await page.evaluate(async investigation => { const data = (await (await fetch(`/api/v1/forensics/evidence?investigationId=${investigation}&limit=100`, { headers: { Authorization: `Bearer ${sessionStorage.getItem('access_token')}` } })).json()).data.items; return data.find(x => x.integrity === 'Verified')?.evidenceId || data[0]?.evidenceId; }, report.investigationId);
  const views = [
    ['investigation-list', '#/dfir-workspace', '#dfir-create'],
    ['overview', `#/dfir-workspace/${report.investigationId}`, '.subnav'],
    ['collections', `#/dfir-workspace/${report.investigationId}?view=collections`, '#dfir-import'],
    ['evidence-browser-export', `#/dfir-workspace/${report.investigationId}?view=evidence`, '#dfir-evidence-search'],
    ['timeline', `#/dfir-workspace/${report.investigationId}?view=timeline`, 'table'],
    ['custody', `#/dfir-workspace/${report.investigationId}?view=custody`, 'table'],
    ['tools', `#/dfir-workspace/${report.investigationId}?view=tools`, 'table'],
    ['readiness', `#/dfir-workspace/${report.investigationId}?view=readiness`, 'article'],
    ['exports', `#/dfir-workspace/${report.investigationId}?view=exports`, 'table'],
    ['artifact-detail', `#/dfir-workspace/${report.investigationId}/evidence/${evidenceId}`, '#evidence-tags'],
    ['collection-wizard', '#/forensic-collections/new', '#forensic-wizard']
  ];
  const screens = [];
  for (const theme of ['dark', 'light']) {
    await page.evaluate(value => localStorage.setItem('theme', value), theme);
    for (const [name, hash, selector] of views) {
      await page.goto(`http://127.0.0.1:8080/${hash}`, { waitUntil: 'networkidle0' });
      await page.waitForSelector(selector, { timeout: 30000 });
      await page.addScriptTag({ content: axeSource });
      const result = await page.evaluate(async () => {
        const axe = await window.axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] } });
        const semantic = [];
        if (!document.querySelector('main') || !document.querySelector('h1')) semantic.push('landmark-or-heading-missing');
        for (const input of document.querySelectorAll('input:not([type=hidden]),textarea,select')) if (!input.labels?.length && !input.getAttribute('aria-label')) semantic.push('unlabelled-control');
        for (const table of document.querySelectorAll('table')) if (!table.querySelector('caption')) semantic.push('table-caption-missing');
        for (const progress of document.querySelectorAll('progress')) if (!progress.getAttribute('aria-label') && !progress.getAttribute('aria-labelledby')) semantic.push('progress-name-missing');
        return { violations: axe.violations.map(v => ({ id: v.id, impact: v.impact, nodes: v.nodes.length })), semantic: [...new Set(semantic)] };
      });
      screens.push({ theme, view: name, ...result });
    }
  }
  await page.goto(`http://127.0.0.1:8080/#/dfir-workspace/${report.investigationId}?view=evidence`, { waitUntil: 'networkidle0' });
  await page.waitForSelector('#dfir-evidence-search button'); await page.focus('#dfir-evidence-search button'); const focused = await page.evaluate(() => document.activeElement?.closest('#dfir-evidence-search') !== null); await page.keyboard.press('Enter');
  const serious = screens.flatMap(x => x.violations).filter(x => x.impact === 'critical' || x.impact === 'serious');
  const output = { schemaVersion: 'sprint34-dfir-accessibility.v1', executedAt: new Date().toISOString(), investigationId: report.investigationId, screens, keyboardOperation: focused ? 'PASS' : 'FAIL', criticalOrSeriousViolations: serious.length, semanticViolations: screens.flatMap(x => x.semantic).length, passed: focused && serious.length === 0 && screens.every(x => x.semantic.length === 0) };
  await browser.close(); fs.writeFileSync(path.join(root, 'artifacts/sprint34-dfir-accessibility.json'), JSON.stringify(output, null, 2)); console.log(JSON.stringify(output, null, 2)); if (!output.passed) process.exitCode = 1;
})().catch(error => { console.error(error); process.exitCode = 1; });
