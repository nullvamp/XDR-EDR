import puppeteer from "../../.tooling/a11y/node_modules/puppeteer-core/lib/esm/puppeteer/puppeteer-core.js";
import fs from "node:fs";

const env=Object.fromEntries(fs.readFileSync(".env","utf8").split(/\r?\n/).filter(x=>x&&!x.startsWith("#")&&x.includes("=")).map(x=>x.split(/=(.*)/s).slice(0,2)));
const browser=await puppeteer.launch({executablePath:process.env.PUPPETEER_EXECUTABLE_PATH||["C:/Program Files/Google/Chrome/Application/chrome.exe","/usr/bin/google-chrome","/usr/bin/chromium"].find(fs.existsSync),headless:true,args:["--no-sandbox"]});
const page=await browser.newPage(), checks=[];
const check=(name,passed,evidence)=>checks.push({name,passed:Boolean(passed),evidence});
await page.goto("http://localhost:8080/#/login",{waitUntil:"networkidle0"});
await page.type('input[name="username"]',env.PLATFORM_BOOTSTRAP_USER); await page.type('input[name="password"]',env.PLATFORM_BOOTSTRAP_PASSWORD);
await Promise.all([page.click("#login button"),page.waitForNetworkIdle()]);

await page.keyboard.press("Tab");
check("skip-link-focus",await page.evaluate(()=>document.activeElement?.classList.contains("skip")),"Tab exposes skip link");
await page.keyboard.press("Enter");
check("skip-link-activation",await page.evaluate(()=>document.activeElement?.id==="content"),"Enter moves focus to main content");

await page.focus("#theme"); const before=await page.evaluate(()=>document.documentElement.dataset.theme);
await page.keyboard.press("Space"); await new Promise(r=>setTimeout(r,100)); const after=await page.evaluate(()=>document.documentElement.dataset.theme);
check("theme-space",before!==after,`${before} -> ${after}`);
await page.focus("#theme");
const focusStyle=await page.evaluate(()=>{const e=document.activeElement,s=getComputedStyle(e);return {tag:e.tagName,outline:s.outline,outlineWidth:s.outlineWidth};});
check("visible-focus",focusStyle.outlineWidth!=="0px"&&focusStyle.outline!=="none",focusStyle);

await page.evaluate(()=>location.hash="#/files"); await page.waitForNetworkIdle();
await page.focus('#file-search input[name="path"]'); await page.keyboard.type("keyboard-probe"); await page.keyboard.press("Tab"); await page.keyboard.down("Shift"); await page.keyboard.press("Tab"); await page.keyboard.up("Shift");
check("tab-and-shift-tab",await page.evaluate(()=>document.activeElement?.name==="path"),"focus returns to path filter");
await page.keyboard.press("Enter"); await new Promise(r=>setTimeout(r,200));
check("form-enter",(await page.evaluate(()=>location.hash)).includes("keyboard-probe"),"search submitted with Enter");

await page.evaluate(()=>{document.querySelector("#content").innerHTML='<ul class="tree"><li role="treeitem" tabindex="0" aria-expanded="true"><a href="#one">one</a><ul role="group"><li role="treeitem" tabindex="-1"><a href="#two">two</a></li></ul></li><li role="treeitem" tabindex="-1"><a href="#three">three</a></li></ul>';window.enableTreeKeyboard();});
await page.focus('[role="treeitem"]'); await page.keyboard.press("End");
check("tree-end",await page.evaluate(()=>document.activeElement?.textContent.trim()==="three"),"End focuses last visible node");
await page.keyboard.press("Home"); await page.keyboard.press("ArrowRight");
check("tree-right",await page.evaluate(()=>document.activeElement?.textContent.trim()==="two"),"Right focuses first child");
await page.keyboard.press("ArrowLeft"); check("tree-left",await page.evaluate(()=>document.activeElement?.textContent.includes("one")),"Left focuses parent");
await page.keyboard.press("ArrowDown"); check("tree-down",await page.evaluate(()=>document.activeElement?.textContent.trim()==="two"),"Down follows visible order");
await page.keyboard.press("ArrowUp"); check("tree-up",await page.evaluate(()=>document.activeElement?.textContent.includes("one")),"Up reverses visible order");

await page.evaluate(()=>{document.querySelector("#content").innerHTML='<button id="opener">Rollback</button><dialog id="d"><h2>Confirm rollback</h2><button id="confirm">Confirm</button><button id="cancel">Cancel</button></dialog>';const d=document.querySelector("#d"),o=document.querySelector("#opener");o.onclick=()=>{d.showModal();document.querySelector("#confirm").focus()};d.addEventListener("close",()=>o.focus());});
await page.focus("#opener"); await page.keyboard.press("Enter");
check("dialog-enter",await page.evaluate(()=>document.querySelector("#d").open&&document.activeElement?.id==="confirm"),"Enter opens modal and focuses destructive confirmation");
await page.keyboard.press("Tab"); check("dialog-tab",await page.evaluate(()=>document.activeElement?.id==="cancel"),"Tab reaches cancel within modal");
await page.keyboard.press("Escape"); check("dialog-escape-return",await page.evaluate(()=>!document.querySelector("#d").open&&document.activeElement?.id==="opener"),"Escape closes and restores trigger focus");

const result={executedAt:new Date().toISOString(),tester:"Automated Puppeteer audit",platform:process.platform,browser:await browser.version(),keys:["Tab","Shift+Tab","Enter","Space","Escape","ArrowUp","ArrowDown","ArrowLeft","ArrowRight","Home","End"],checks,passed:checks.every(x=>x.passed)};
fs.mkdirSync("artifacts",{recursive:true});fs.writeFileSync("artifacts/sprint3e-keyboard-matrix.json",JSON.stringify(result,null,2));console.log(JSON.stringify(result,null,2));await browser.close();if(!result.passed)process.exitCode=1;
