const fs = require("fs");
const path = require("path");
const root = path.resolve(__dirname, "../..");
const { launch } = require(path.join(root, ".tooling/a11y/node_modules/puppeteer-core"));
const axeSource = fs.readFileSync(path.join(root, ".tooling/a11y/node_modules/axe-core/axe.min.js"), "utf8");
const env = Object.fromEntries(fs.readFileSync(path.join(root, ".env"), "utf8").split(/\r?\n/).filter(x => /^[^#][^=]*=/.test(x)).map(x => { const i=x.indexOf("="); return [x.slice(0,i),x.slice(i+1)]; }));
(async () => {
  const browser=await launch({headless:true,executablePath:"C:/Program Files/Google/Chrome/Application/chrome.exe"}),page=await browser.newPage();
  page.setDefaultTimeout(20000);await page.goto("http://localhost:8080",{waitUntil:"domcontentloaded"});
  const auth=await page.evaluate(async c=>await(await fetch("/api/v1/auth/token",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(c)})).json(),{username:env.PLATFORM_BOOTSTRAP_USER,password:env.PLATFORM_BOOTSTRAP_PASSWORD});
  await page.evaluate(token=>sessionStorage.setItem("access_token",token),auth.access_token);
  const endpoint=await page.evaluate(async()=>{const h={Authorization:`Bearer ${sessionStorage.getItem("access_token")}`},x=await(await fetch("/api/v1/endpoints?pageSize=100",{headers:h})).json();return x.data.items[0];});
  if(!endpoint)throw Error("No endpoint available for containment accessibility qualification");
  const screens=[];
  for(const theme of ["dark","light"]){
    await page.evaluate(x=>localStorage.setItem("theme",x),theme);await page.goto(`http://localhost:8080/#/endpoints/${endpoint.id}`,{waitUntil:"domcontentloaded"});
    await page.waitForSelector("#containment-title");await page.addScriptTag({content:axeSource});
    const base=await page.evaluate(async()=>{const result=await axe.run(document,{runOnly:{type:"tag",values:["wcag2a","wcag2aa","wcag21aa"]}});return result.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.length}));});
    screens.push({name:`containment-status-${theme}`,theme,violations:base});
    await page.click("#containment-open");await page.waitForSelector("#containment-dialog[open]");
    const dialog=await page.evaluate(async()=>{const result=await axe.run(document,{runOnly:{type:"tag",values:["wcag2a","wcag2aa","wcag21aa"]}});return{violations:result.violations.map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.length})),focusInside:document.querySelector("#containment-dialog").contains(document.activeElement),labelled:document.querySelector("#containment-dialog").getAttribute("aria-labelledby")==="containment-dialog-title"};});
    screens.push({name:`containment-confirmation-${theme}`,theme,...dialog});await page.click("#containment-close");
  }
  await page.goto(`http://localhost:8080/#/endpoints/${endpoint.id}`,{waitUntil:"domcontentloaded"});await page.waitForSelector("#containment-title");await page.focus("#containment-open");await page.keyboard.press("Enter");const keyboard=await page.evaluate(()=>document.querySelector("#containment-dialog")?.open&&document.querySelector("#containment-dialog").contains(document.activeElement));await page.click("#containment-close");const restored=await page.evaluate(()=>document.activeElement?.id==="containment-open");
  const serious=screens.flatMap(x=>x.violations||[]).filter(x=>x.impact==="critical"||x.impact==="serious"),report={schemaVersion:"sprint18-containment-accessibility.v1",executedAt:new Date().toISOString(),endpointId:endpoint.id,tool:`axe-core ${require(path.join(root,".tooling/a11y/node_modules/axe-core/package.json")).version}`,browser:await browser.version(),screens,keyboardOperation:keyboard?"PASS":"FAIL",focusManagement:keyboard&&restored?"PASS":"FAIL",criticalOrSeriousViolations:serious.length,passed:keyboard&&restored&&serious.length===0&&screens.filter(x=>x.name.includes("confirmation")).every(x=>x.focusInside&&x.labelled)};
  await browser.close();fs.writeFileSync(path.join(root,"artifacts/sprint18-containment-accessibility.json"),JSON.stringify(report,null,2));process.stdout.write(JSON.stringify(report,null,2));process.exitCode=report.passed?0:1;
})().catch(e=>{console.error(e);process.exitCode=1;});
