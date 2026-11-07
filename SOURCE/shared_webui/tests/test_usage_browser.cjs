/* Labelled native-browser fixture using production chart JS/CSS. Deployed
   traffic/API/CSV acceptance is separate; these measurements are synthetic. */
const fs=require('fs'),path=require('path'),assert=require('assert/strict'),{chromium}=require('playwright');
const root=path.resolve(__dirname,'..'),read=n=>fs.readFileSync(path.join(root,n),'utf8');
const source=process.env.SBOX_USAGE_SOURCE?fs.readFileSync(process.env.SBOX_USAGE_SOURCE,'utf8'):read('frontend-src/shared/usage.js');
function data(n){return{timezone:'America/New_York',start:1793505600,end:1793505600+n*3600,totals:{upload_bytes:123,download_bytes:456},buckets:Array.from({length:n},(_,i)=>({start:1793505600+i*3600,end:1793509200+i*3600,up:i===0?123:null,down:i===0?456:null,state:i===0?'partial':'before_collection'})),incomplete:true};}
const fit=async p=>p.locator('.usage-tooltip').evaluate(e=>{const r=e.getBoundingClientRect();return e.hidden||(r.left>=0&&r.right<=innerWidth+1&&r.top>=0&&r.bottom<=innerHeight+1)});
(async()=>{const b=await chromium.launch(process.env.SBOX_BROWSER_EXE?{executablePath:process.env.SBOX_BROWSER_EXE}:{});let cases=0;
try{const p=await b.newPage();for(const lang of ['en','zh'])for(const theme of ['light','dark','system'])for(const width of [320,360,375,390,414,600,640,768,1024,1280,1440,1920])for(const n of [1,25,169]){
 await p.setViewportSize({width:1920,height:900});await p.goto('about:blank');
 await p.setContent(`<style>${read('frontend/portal.css')}\n${read('frontend-src/shared/usage.css')}</style><main style="padding:24px"><div style="height:950px"></div><div id="chart"></div><button id="next">Next action</button><div style="height:1000px"></div></main>`);
 await p.evaluate(theme=>document.documentElement.dataset.theme=theme,theme);await p.addScriptTag({content:source});await p.evaluate(({d,lang})=>document.querySelector('#chart').innerHTML=SBOXUsage.render(d,lang),{d:data(n),lang});
 const bar=p.locator('.usage-bar').first();await bar.scrollIntoViewIfNeeded();await bar.evaluate(e=>e.blur());await bar.focus();await p.locator('.usage-tooltip').waitFor({state:'visible'});
 await p.setViewportSize({width,height:900});await p.waitForTimeout(35);
 assert(await fit(p),`${lang}/${theme}/${width}/${n}: resize must keep the focused tooltip inside the viewport or close it`);
 await bar.scrollIntoViewIfNeeded();await bar.evaluate(e=>e.blur());await bar.focus();await p.locator('.usage-tooltip').waitFor({state:'visible'});assert(await fit(p),'Newly focused tooltip must fit');
 const column=await p.locator('.usage-up').first().boundingBox();assert(column.width>0&&column.width<=24,'Single source columns must remain narrow in CSS pixels');
 const focus=await bar.evaluate(e=>(e.querySelector('.usage-focus')||e.querySelector('.usage-hit')).getBoundingClientRect().width);assert(focus<=34,'The visible keyboard focus band must stay narrow even when the hit target spans one whole interval');
 await p.keyboard.press('Escape');assert(await p.locator('.usage-tooltip').evaluate(e=>e.hidden),'Escape dismisses without moving chart focus');assert(await bar.evaluate(e=>document.activeElement===e));
 if(theme==='dark'&&width===640&&n===25){
   await p.evaluate(()=>{const dialog=document.createElement('dialog');dialog.id='usage-dialog';dialog.style.cssText='width:min(500px,85vw);max-height:80vh;overflow:auto';document.body.append(dialog);dialog.append(document.querySelector('#chart'));dialog.showModal();});
   await bar.scrollIntoViewIfNeeded();await bar.evaluate(e=>e.blur());await bar.focus();await p.locator('.usage-tooltip').waitFor({state:'visible'});
   assert(await p.locator('.usage-tooltip').evaluate(e=>{const r=e.getBoundingClientRect();return !!document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)?.closest('.usage-tooltip')}),'Admin dialog tooltip must be in the native top layer and hoverable');
   await p.evaluate(()=>document.querySelector('#usage-dialog').close());await p.waitForTimeout(35);assert(await p.locator('.usage-tooltip').evaluate(e=>e.hidden&&!e.textContent),'Closing a dialog must clear its tooltip');
   await p.evaluate(()=>{document.querySelector('main').append(document.querySelector('#chart'));document.querySelector('#usage-dialog').remove()});
 }
 if(theme==='light'&&width===640&&n===25){
   await bar.evaluate(e=>e.blur());await p.mouse.move(0,0);await bar.hover();await p.locator('.usage-tooltip').waitFor({state:'visible'});
   const tip=await p.locator('.usage-tooltip').boundingBox();await p.mouse.move(tip.x+tip.width/2,tip.y+tip.height/2);assert(await p.locator('.usage-tooltip').isVisible(),'Pointer can inspect the tooltip without it disappearing');
   await p.keyboard.press('Escape');assert(await p.locator('.usage-tooltip').evaluate(e=>e.hidden));
   await p.evaluate(()=>document.documentElement.style.fontSize='400%');await p.setViewportSize({width:320,height:900});await bar.scrollIntoViewIfNeeded();await bar.focus();await p.locator('.usage-tooltip').waitFor({state:'visible'});
   assert(await fit(p),'Enlarged tooltip text must fit and remain scrollable');assert(await p.locator('.usage-tooltip').evaluate(e=>parseFloat(getComputedStyle(e).fontSize)>=48),'Tooltip text must follow text enlargement');
   await p.evaluate(()=>document.documentElement.style.fontSize='');await p.setViewportSize({width,height:900});
 }
 await bar.scrollIntoViewIfNeeded();await bar.evaluate(e=>e.blur());await bar.focus();await p.keyboard.press(n===1?'Home':'End');assert(await p.locator('.usage-bar').last().evaluate(e=>document.activeElement===e),'Chart keyboard navigation reaches the final bucket');
 await p.locator('.usage-bar').last().evaluate(e=>e.blur());await p.locator('.usage-bar').last().focus();await p.locator('.usage-tooltip').waitFor({state:'visible'});await p.evaluate(()=>scrollTo(0,0));
 // Scroll delivery runs on the browser's rendering schedule. A fixed 35ms
 // sleep races a busy CI renderer: observe both the intended geometry and
 // the real tooltip state instead. A missing scroll handler still fails.
 try {
  await p.waitForFunction(()=>{const a=[...document.querySelectorAll('.usage-bar')].at(-1),r=(a.querySelector('.usage-focus')||a).getBoundingClientRect();return scrollY===0&&r.top>=innerHeight;},null,{timeout:2000});
  await p.locator('.usage-tooltip').waitFor({state:'hidden',timeout:2000});
 } catch(error) {
  const actual=await p.locator('.usage-bar').last().evaluate(e=>({anchor:e.getBoundingClientRect().toJSON(),scrollX,scrollY,viewport:[innerWidth,innerHeight],tooltipHidden:document.querySelector('.usage-tooltip').hidden}));
  throw new Error(`${lang}/${theme}/${width}/${n}: offscreen tooltip did not settle: ${JSON.stringify(actual)}`);
 }
 assert(await p.locator('.usage-tooltip').evaluate(e=>e.hidden&&!e.textContent),'Offscreen anchor must close and clear its tooltip');
 await bar.scrollIntoViewIfNeeded();await bar.evaluate(e=>e.blur());await bar.focus();await p.locator('.usage-tooltip').waitFor({state:'visible'});await p.evaluate(()=>document.querySelector('#chart').remove());
 await p.waitForTimeout(35);assert(await p.locator('.usage-tooltip').evaluate(e=>e.hidden&&!e.textContent),'Removing a chart must clear its private tooltip');cases++;
}console.log(JSON.stringify({fixture:true,browser:b.version(),scope:'production usage chart, actual CSS/DOM, resize/Escape/offscreen/removal/keyboard and bounded columns; 2 locales x 3 themes x 12 widths x 3 bucket counts',cases,passed:true}));}finally{await b.close();}})().catch(e=>{console.error(e.message);process.exitCode=1});
