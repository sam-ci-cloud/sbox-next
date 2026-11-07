/* Native browser fixture, never a substitute for deployed UI acceptance.
   Run the production scroll listener: an opening click may queue scrolling. */
const fs=require('fs'),path=require('path'),assert=require('assert/strict'),{chromium}=require('playwright');
const root=path.resolve(__dirname,'..'),read=n=>fs.readFileSync(path.join(root,n),'utf8');
const scrollListener=read('frontend-src/js/90-events.js').split('\n').find(line=>line.includes("document.addEventListener('scroll'"));
(async()=>{const browser=await chromium.launch(process.env.SBOX_BROWSER_EXE?{executablePath:process.env.SBOX_BROWSER_EXE}:{});let cases=0;
try{const p=await browser.newPage();for(const lang of ['en','zh'])for(const width of [320,360,375,390,414,600,640,768,1024,1280,1440,1920])for(const count of [3,35]){
 await p.setViewportSize({width,height:900});await p.setContent(`<style>${read('frontend/style.css')}</style><main style="padding:24px"><div style="height:1000px"></div><details class="menu"><summary>${lang==='zh'?'更多操作':'More actions'}</summary><div class="menu-list" popover="manual">${Array.from({length:count},(_,i)=>`<button>${lang==='zh'?'使用者及流量操作':'User and allowance action'} ${i+1}</button>`).join('')}</div></details><div style="height:1300px"></div></main><dialog id="modal"></dialog>`);
 await p.addScriptTag({content:"const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];\n"+read('frontend-src/js/52-adaptive-charts.js')});
 await p.addScriptTag({content:"document.addEventListener('toggle',e=>{if(e.target.matches('details.menu'))placeActionMenu(e.target)},true);\n"+scrollListener});
 await p.locator('summary').click();await p.evaluate(()=>scrollBy(0,1));await p.waitForTimeout(100);
 let g=await p.locator('.menu-list').evaluate(e=>{const r=e.getBoundingClientRect();return{open:e.parentElement.open,popover:e.matches(':popover-open'),x:r.x,y:r.y,right:r.right,bottom:r.bottom}});
 assert(g.open&&g.popover,`${lang}/${width}/${count}: opening/following scroll must preserve the visible anchored menu`);assert(g.x>=0&&g.right<=width+1&&g.y>=0&&g.bottom<=900,'Menu must fit the viewport');
 if(count===35){await p.locator('.menu-list button').last().scrollIntoViewIfNeeded();await p.waitForTimeout(50);assert(await p.locator('.menu-list').evaluate(e=>e.matches(':popover-open')),'Scrolling inside a long menu must preserve it');}
 await p.evaluate(()=>scrollTo(0,0));await p.waitForTimeout(100);assert.equal(await p.locator('details.menu').evaluate(e=>e.open),false,'Close a menu whose anchor has left the viewport');cases++;
}console.log(JSON.stringify({fixture:true,scope:'native popover and real production scroll handler; both locales, 12 widths, short/scrolling menus',cases,passed:true}));}finally{await browser.close();}})().catch(e=>{console.error(e.message);process.exitCode=1});
