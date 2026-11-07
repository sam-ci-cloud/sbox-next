/* Real-browser UI audit: screenshots + measured overflow, contrast, target size
   and accessible names across widths/themes/languages.
   Usage: node ui_audit.cjs ORIGIN OUTDIR LABEL [--pages a,b] [--full]
   Requires Playwright on the TEST WORKSTATION only (never on the VPS). */
const {chromium}=require('playwright');
const fs=require('fs');
const path=require('path');
const [origin,out,label,...rest]=process.argv.slice(2);
const opt=k=>{const i=rest.indexOf(k);return i>=0?rest[i+1]:undefined;};
const full=rest.includes('--full');
const password=process.env.SBOX_AUDIT_PASSWORD||opt('--password')||'Fixture-admin-password-2026';
const fixture=opt('--fixture-html');
const pages=(opt('--pages')||'overview,inbounds,users,subscriptions,policy,traffic,logs,security,certificates,updates,settings,api').split(',');
const widths=(opt('--widths')||'320,360,375,390,414,600,640,768,1024,1280,1440,1920').split(',').map(Number);
fs.mkdirSync(out,{recursive:true});
const host=new URL(origin).hostname;
if(!/^[A-Za-z0-9_-]+$/.test(label))throw new Error('Use a simple alphanumeric report label');
if(!widths.length||widths.some(w=>!Number.isInteger(w)||w<240||w>7680))throw new Error('Invalid audit widths');
let browser;

function luminanceJS(){
  /* runs in page */
  const parse=c=>{const m=c.match(/rgba?\(([^)]+)\)/);if(!m)return null;const p=m[1].split(/[ ,/]+/).filter(Boolean).map(Number);return {r:p[0],g:p[1],b:p[2],a:p.length>3?p[3]:1};};
  const lin=v=>{v/=255;return v<=0.03928?v/12.92:Math.pow((v+0.055)/1.055,2.4);};
  const L=c=>0.2126*lin(c.r)+0.7152*lin(c.g)+0.0722*lin(c.b);
  const blend=(fg,bg)=>({r:fg.r*fg.a+bg.r*(1-fg.a),g:fg.g*fg.a+bg.g*(1-fg.a),b:fg.b*fg.a+bg.b*(1-fg.a),a:1});
  const bgOf=el=>{const stack=[];for(let e=el;e;e=e.parentElement){const s=getComputedStyle(e);const c=parse(s.backgroundColor);if(c&&c.a>0)stack.push(c);if(c&&c.a>=1)break;if(s.backgroundImage&&s.backgroundImage!=='none'&&!s.backgroundImage.startsWith('linear'))return null;}let base={r:255,g:255,b:255,a:1};const root=parse(getComputedStyle(document.documentElement).backgroundColor);if(root&&root.a>=1)base=root;for(let i=stack.length-1;i>=0;i--)base=blend(stack[i],base);return base;};
  const fails=[];let checked=0;const seen=new Set();
  const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
  while(walker.nextNode()){
    const n=walker.currentNode;if(!n.textContent.trim())continue;const el=n.parentElement;if(!el||seen.has(el))continue;seen.add(el);
    const r=el.getBoundingClientRect();if(r.width===0||r.height===0)continue;const s=getComputedStyle(el);if(s.visibility==='hidden'||s.display==='none'||Number(s.opacity)===0)continue;
    if(el.closest('[hidden],dialog:not([open]),.sr,.skip:not(:focus),[aria-hidden=true]'))continue;
    if(el.closest('svg'))continue;
    const fg=parse(s.color);const bg=bgOf(el);if(!fg||!bg)continue;const c=blend(fg,bg);
    const l1=L(c),l2=L(bg);const ratio=(Math.max(l1,l2)+0.05)/(Math.min(l1,l2)+0.05);
    const size=parseFloat(s.fontSize);const bold=Number(s.fontWeight)>=700;const large=size>=24||(bold&&size>=18.66);
    const need=large?3:4.5;checked++;
    if(ratio+1e-9<need&&!el.disabled&&!el.closest('[disabled],[aria-disabled=true]'))fails.push({text:n.textContent.trim().slice(0,40),ratio:Math.round(ratio*100)/100,need,size,cls:el.className&&String(el.className).slice(0,40),tag:el.tagName});
  }
  return {checked,fails};
}
function targetsJS(mobile){
  const out=[];let checked=0;
  for(const el of document.querySelectorAll('a[href],button,input:not([type=hidden]),select,textarea,summary,[role=button],[tabindex]:not([tabindex="-1"])')){
    const r=el.getBoundingClientRect();if(r.width===0||r.height===0)continue;const s=getComputedStyle(el);if(s.visibility==='hidden'||s.display==='none')continue;
    if(el.closest('[hidden],dialog:not([open])'))continue;if(el.matches('.skip'))continue;
    // WCAG 2.5.8 inline exception: links inside running text
    const inline=el.tagName==='A'&&getComputedStyle(el).display==='inline'&&el.closest('p,li,td');
    checked++;
    if(!inline&&(r.width<24||r.height<24))out.push({kind:'below-24px',tag:el.tagName,text:(el.innerText||el.getAttribute('aria-label')||el.name||'').trim().slice(0,30),w:Math.round(r.width),h:Math.round(r.height)});
    else if(mobile&&!inline&&el.matches('button,select,input:not([type=checkbox]):not([type=radio]),#nav a,summary')&&r.height<44)out.push({kind:'mobile-below-44px',tag:el.tagName,text:(el.innerText||el.getAttribute('aria-label')||el.name||'').trim().slice(0,30),w:Math.round(r.width),h:Math.round(r.height)});
  }
  return {checked,issues:out};
}
async function axNames(page){
  const client=await page.context().newCDPSession(page);
  const {nodes}=await client.send('Accessibility.getFullAXTree');
  const roles=new Set(['button','link','textbox','combobox','checkbox','searchbox','spinbutton','radio','switch','menuitem','tab','listbox']);
  const missing=[];let checked=0;
  for(const n of nodes){if(n.ignored)continue;const role=n.role&&n.role.value;if(!roles.has(role))continue;checked++;const name=(n.name&&n.name.value||'').trim();if(!name)missing.push({role,id:n.backendDOMNodeId});}
  await client.detach();
  return {checked,missing};
}
(async()=>{
  const args=[];
  if(rest.includes('--map-loopback'))args.push('--host-resolver-rules=MAP '+host+' 127.0.0.1');
  browser=await chromium.launch({executablePath:process.env.SBOX_BROWSER_EXE,headless:true,args});
  const results={label,origin:fixture?'synthetic local HTML':origin,fixture:Boolean(fixture),scope:'Browser UI checks only; not VPN, firewall or production acceptance',generated:new Date().toISOString(),browser:browser.version(),runs:[],readinessFailures:[]};
  const errors=[];
  for(const lang of (opt('--langs')||'en,zh').split(',')){
    for(const theme of (opt('--themes')||'dark,light').split(',')){
      const context=await browser.newContext({ignoreHTTPSErrors:rest.includes('--fixture-insecure-tls'),viewport:{width:1440,height:900},locale:lang==='zh'?'zh-TW':'en-GB',colorScheme:theme});
      await context.addInitScript(([lang,theme])=>{try{localStorage.setItem('sbox-lang',lang);localStorage.setItem('sbox-theme',theme);}catch(e){}},[lang,theme]);
      const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
      if(fixture)await page.setContent(fs.readFileSync(fixture,'utf8'));
      else await page.goto(origin,{waitUntil:'networkidle'});
      await page.locator('#login-form input[name=username]').fill('admin');
      await page.locator('#login-form input[name=password]').fill(password);
      await page.locator('#login-form button[type=submit], #login-form button').first().click();
      await page.locator('#shell').waitFor({state:'visible'});
      for(const width of widths){
        await page.setViewportSize({width,height:width<700?844:900});
        for(const p of pages){
          await page.evaluate(h=>{location.hash=h;},p);
          await page.waitForFunction(()=>{const c=document.querySelector('#content');return c&&!c.querySelector('.loading,[aria-busy=true]')&&!/Loading current state|正在讀取/.test(c.textContent)&&c.textContent.length>20;},null,{timeout:15000}).catch(()=>{results.readinessFailures.push({lang,theme,width,page:p});});
          await page.waitForTimeout(120);
          const overflow=await page.evaluate(()=>({doc:document.documentElement.scrollWidth,vw:innerWidth,over:document.documentElement.scrollWidth>innerWidth+1}));
          const contrast=await page.evaluate(luminanceJS);
          const targets=await page.evaluate(targetsJS,width<=430);
          const ax=await axNames(page);
          const run={lang,theme,width,page:p,overflow,contrastChecked:contrast.checked,contrastFails:contrast.fails,targetsChecked:targets.checked,targetIssues:targets.issues,ax};
          results.runs.push(run);
          const shoot=full||((width===1440||width===390)&&lang==='en'&&theme==='dark')||((p==='overview'||p==='users')&&(lang==='en'&&theme==='dark'||width===1440||width===390));
          if(shoot)await page.screenshot({path:path.join(out,`${label}-${p}-${width}-${theme}-${lang}.png`),fullPage:true});
        }
      }
      await context.close();
    }
  }
  results.pageErrors=errors;
  const sum={runs:results.runs.length,overflowRuns:results.runs.filter(r=>r.overflow.over).length,contrastFailRuns:results.runs.filter(r=>r.contrastFails.length).length,
    contrastFailures:results.runs.reduce((a,r)=>a+r.contrastFails.length,0),target24:results.runs.reduce((a,r)=>a+r.targetIssues.filter(i=>i.kind==='below-24px').length,0),
    mobile44:results.runs.reduce((a,r)=>a+r.targetIssues.filter(i=>i.kind==='mobile-below-44px').length,0),axMissing:results.runs.filter(r=>r.ax).reduce((a,r)=>a+r.ax.missing.length,0),pageErrors:errors.length};
  const expected=pages.length*widths.length*(opt('--langs')||'en,zh').split(',').length*(opt('--themes')||'dark,light').split(',').length;
  sum.expectedRuns=expected;
  sum.readinessFailures=results.readinessFailures.length;
  sum.emptyChecks=results.runs.filter(r=>!r.contrastChecked||!r.targetsChecked||!r.ax?.checked).length;
  sum.passed=expected>0&&sum.runs===expected&&['overflowRuns','contrastFailures','target24','mobile44','axMissing','pageErrors','readinessFailures','emptyChecks'].every(key=>sum[key]===0);
  results.summary=sum;
  fs.writeFileSync(path.join(out,label+'-audit.json'),JSON.stringify(results,null,1));
  console.log(JSON.stringify(sum));
  if(!sum.passed)process.exitCode=1;
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(async()=>{if(browser)await browser.close();});
