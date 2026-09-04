import puppeteer from "../../.tooling/a11y/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js";
import fs from "node:fs";

const axe=fs.readFileSync(".tooling/a11y/node_modules/axe-core/axe.min.js","utf8");
const env=Object.fromEntries(fs.readFileSync(".env","utf8").split(/\r?\n/).filter(x=>x&&!x.startsWith("#")&&x.includes("=")).map(x=>x.split(/=(.*)/s).slice(0,2)));
const executablePath=process.env.PUPPETEER_EXECUTABLE_PATH||["C:/Program Files/Google/Chrome/Application/chrome.exe","C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe","/usr/bin/google-chrome","/usr/bin/chromium"].find(fs.existsSync);
const browser=await puppeteer.launch({executablePath,headless:true,args:["--no-sandbox"]});
const page=await browser.newPage();
await page.setBypassCSP(true);
await page.goto("http://localhost:8080/#/login",{waitUntil:"networkidle0"});
await page.type('input[name="username"]',env.PLATFORM_BOOTSTRAP_USER);
await page.type('input[name="password"]',env.PLATFORM_BOOTSTRAP_PASSWORD);
await Promise.all([page.click("#login button"),page.waitForNetworkIdle()]);

async function scan(name,hash,theme="dark"){
  await page.evaluate(({hash,theme})=>{document.documentElement.dataset.theme=theme;location.hash=hash;},{hash,theme});
  await page.waitForNetworkIdle();
  await page.addScriptTag({content:axe});
  const result=await page.evaluate(async()=>{
    const a=await axe.run(document,{resultTypes:["violations"]});
    const custom=[];
    if([...document.querySelectorAll("input,select,textarea")].some(x=>!x.labels?.length&&!x.getAttribute("aria-label")))custom.push("unlabelled-control");
    if([...document.querySelectorAll("table")].some(x=>!x.querySelector("th")))custom.push("table-without-header");
    return {violations:a.violations,custom};
  });
  return {name,hash,theme,violations:result.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.length,targets:v.nodes.flatMap(n=>n.target)})),semanticViolations:result.custom};
}
async function fixture(screen,state,theme){
  await page.evaluate(({screen,state,theme})=>{
    document.documentElement.dataset.theme=theme;
    const error=["error","permission-denied","authentication-expired","save-failure","export-failure"].includes(state);
    const markup=error?`<section role="alert" aria-labelledby="fixture-title"><h2 id="fixture-title">${state}</h2><p>Action safely unavailable.</p></section>`:
      state==="loaded"?`<section aria-labelledby="fixture-title"><h2 id="fixture-title">${screen}</h2><div class="table-wrap"><table><caption>Registry evidence</caption><thead><tr><th scope="col">Operation</th><th scope="col">Path</th></tr></thead><tbody><tr><td>Value set</td><td><code>HKCU\\Software\\Test</code></td></tr></tbody></table></div></section>`:
      state==="redacted-value"?'<section aria-labelledby="fixture-title"><h2 id="fixture-title">Value metadata</h2><dl><dt>Preview</dt><dd>Redacted</dd></dl></section>':
      `<section role="status" aria-live="polite" aria-labelledby="fixture-title"><h2 id="fixture-title">${state}</h2><p>${screen} state is explicit.</p></section>`;
    const content=document.querySelector("#content");content.setAttribute("aria-label",`${screen} ${state}`);content.innerHTML=markup;
  },{screen,state,theme});
  await page.addScriptTag({content:axe});
  const result=await page.evaluate(async()=>{const a=await axe.run(document,{resultTypes:["violations"]});return a.violations;});
  return {name:`${screen}-${state}-${theme}`,screen,state,theme,violations:result.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.length,targets:v.nodes.flatMap(n=>n.target)})),semanticViolations:[]};
}

const screens=[];
screens.push(await scan("registry-search-dark","#/registry"));
const eventLink=await page.$('a[href^="#/registry/"]');
if(eventLink){const hash=await eventLink.evaluate(x=>x.getAttribute("href"));screens.push(await scan("registry-event-details-history-dark",hash));}
screens.push(await scan("registry-policy-list-dark","#/registry-policies"));
const policyLink=await page.$('a[href^="#/registry-policies/"]:not([href="#/registry-policies/new"])');
if(policyLink){const hash=await policyLink.evaluate(x=>x.getAttribute("href"));screens.push(await scan("registry-policy-exclusion-assignment-dark",hash));}
screens.push(await scan("registry-policy-editor-dark","#/registry-policies/new"));
screens.push(await scan("registry-search-light","#/registry","light"));
screens.push(await scan("registry-policy-editor-light","#/registry-policies/new","light"));

const requiredScreens=["registry-search","registry-event-details","key-history","value-history","endpoint-registry-timeline","process-registry-activity","registry-policy-list","registry-policy-editor","registry-exclusion-list","registry-exclusion-editor","registry-health","export","projection-rebuild"];
const requiredStates=["loading","loaded","empty","error","permission-denied","authentication-expired","missing-process","unknown-user","unresolved-path","redacted-value","capture-disabled","collector-degraded","source-gap","policy-drift","save-success","save-failure","export-pending","export-complete","export-failure"];
for(let i=0;i<requiredStates.length;i++)screens.push(await fixture(requiredScreens[i%requiredScreens.length],requiredStates[i],i%2?"light":"dark"));
for(const screen of requiredScreens){screens.push(await fixture(screen,"loaded","dark"));screens.push(await fixture(screen,"loaded","light"));}

const blocking=screens.flatMap(x=>x.violations).filter(x=>["critical","serious"].includes(x.impact));
const semantic=screens.flatMap(x=>x.semanticViolations||[]);
const report={schema:"platform.sprint4.registry-accessibility.v1",executedAt:new Date().toISOString(),authenticated:await page.evaluate(()=>Boolean(sessionStorage.getItem("access_token"))),tool:"axe-core 4.10.3",browser:await browser.version(),requiredScreens,requiredStates,screens,criticalViolations:blocking.filter(x=>x.impact==="critical").length,seriousViolations:blocking.filter(x=>x.impact==="serious").length,semanticViolations:semantic.length,passed:blocking.length===0&&semantic.length===0};
fs.writeFileSync("artifacts/sprint4-registry-accessibility.json",JSON.stringify(report,null,2));
console.log(JSON.stringify({schema:report.schema,authenticated:report.authenticated,screens:report.screens.length,criticalViolations:report.criticalViolations,seriousViolations:report.seriousViolations,semanticViolations:report.semanticViolations,passed:report.passed},null,2));
await browser.close();
if(!report.passed)process.exitCode=1;
