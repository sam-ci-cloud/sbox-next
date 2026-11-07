/* Connect & Export Center acceptance on the REAL panel HTTPS server (synthetic fixture users).
   Admin console and the personal subscription page render the same shared component.
   Checks: one entry point per user, grouped steps, copy-only clipboard, QR decoded with jsQR
   (subscription URL vs single-node URI), downloads and filenames, sing-box conditional reveal,
   basic JSON profile note, endpoint selection, no overflow, keyboard/focus, screenshots at
   6 widths x en/zh x light/dark. Not VPN evidence.
   SBOX_TEST_HOST=127.0.0.1 runs without a hostname mapping (sandboxed local runs). */
const fs=require('fs'),path=require('path'),assert=require('node:assert/strict'),{spawn}=require('child_process'),{chromium}=require('playwright'),sharp=require('sharp'),jsQR=require('jsqr');
const out=path.resolve(process.argv[2]||'.build/connect-browser');fs.mkdirSync(out,{recursive:true});
const pass='Fixture-admin-password-2026',port=Number(process.env.SBOX_TEST_PORT||19843),host=process.env.SBOX_TEST_HOST||'panel.sbox.test',origin=`https://${host}:${port}`;
const WIDTHS=[360,390,768,1024,1440,1920],THEMES=['light','dark'],LANGS=['en','zh'];
let fixture,browser;const rows=[];
async function decodeQr(locator){await locator.waitFor();await locator.evaluate(i=>i.decode());const {data,info}=await sharp(await locator.screenshot()).ensureAlpha().raw().toBuffer({resolveWithObject:true});return jsQR(new Uint8ClampedArray(data),info.width,info.height)?.data;}
async function geometry(p,width){return p.evaluate(width=>{const r=[...document.querySelectorAll('.xc button,.xc input[type=radio],.xc summary')].filter(x=>x.offsetParent).map(x=>x.getBoundingClientRect());return{overflow:document.documentElement.scrollWidth>innerWidth+1,outside:r.filter(b=>b.left<-1||b.right>width+1).length,smallButtons:[...document.querySelectorAll('.xc-actions button')].filter(x=>x.offsetParent&&x.getBoundingClientRect().height<40).length}},width);}
async function radio(p,name,value){await p.locator(`.xc input[type=radio][data-xc="${name}"][value="${value}"]`).check();await p.locator(`.xc input[data-xc="${name}"][value="${value}"]:checked`).waitFor();}
(async()=>{
 const args=['--no-proxy-server'];if(!/^[\d.]+$/.test(host))args.push('--host-resolver-rules=MAP '+host+' 127.0.0.1');
 fixture=spawn('python3',[path.join(__dirname,'dev_panel.py'),'--users','3','--port',String(port),'--host',host,'--work',path.join(out,'fixture')],{stdio:['ignore','pipe','pipe']});
 await new Promise((resolve,reject)=>{fixture.stdout.once('data',resolve);fixture.on('exit',c=>reject(new Error('fixture exited '+c)));setTimeout(()=>reject(new Error('fixture startup timeout')),15000).unref()});
 browser=await chromium.launch({executablePath:process.env.SBOX_BROWSER_EXE,args});
 let landing=null;
 for(const lang of LANGS)for(const theme of THEMES)for(const width of WIDTHS){
  const full=width===1440&&theme==='light';
  const c=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width,height:1000},colorScheme:theme,acceptDownloads:true}),p=await c.newPage();const errors=[],downloads=[],qrRequests=[];
  await p.addInitScript(lang=>{localStorage.setItem('sbox-lang',lang);Object.defineProperty(navigator,'clipboard',{value:{writeText:async text=>{window.copiedConnection=text}}})},lang);
  p.on('pageerror',e=>errors.push(e.message));p.on('download',d=>downloads.push(d));p.on('request',r=>{if(r.url().endsWith('/api/v1/qr'))qrRequests.push(r.postDataJSON())});
  await p.goto(origin);await p.locator('#login-form input[name=username]').fill('admin');await p.locator('#login-form input[name=password]').fill(pass);await p.locator('#login-submit').click();await p.locator('#shell').waitFor({state:'visible'});
  const issued=await p.evaluate(async()=>{const me=await(await fetch('/api/v1/auth/me')).json(),users=await(await fetch('/api/v1/users')).json(),id=users.find(u=>!u.protected&&u.enabled).id;const post=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':me.csrf},body:JSON.stringify(b)});await post('/api/v1/subscriptions/settings',{landing_page:true});const r=await post('/api/v1/subscriptions/rotate-token',{id});if(!r.ok)throw Error('issue HTTP '+r.status);return{id,...await r.json()}});
  assert.ok(issued.catalog&&issued.catalog.clients.length===2,'connection payload carries the shared catalog');
  await p.evaluate(()=>location.hash='users');
  const row=p.locator(`tr:has([data-action=user-share][data-id="${issued.id}"])`);await row.waitFor();
  assert.equal(await row.locator('[data-action=user-export]').count(),0,'no separate download action per user');
  await row.locator(`[data-action=user-share][data-id="${issued.id}"]`).click();await p.locator('.xc').waitFor();
  assert.equal(await p.locator('.xc-step:visible').count(),4,'four grouped steps');assert.equal(await p.locator('#modal-foot button').count(),1,'footer: Close only');
  assert.equal(await p.locator('.xc fieldset.xc-step > legend').count(),4);
  const url=p.locator('.xc-out input[readonly]').first();assert.equal(await url.inputValue(),issued.urls.global,'default: Mihomo, general browsing, automatic address, subscription');
  if(full){
   await p.locator('[data-xc-act=copy-url]').click();assert.equal(await p.evaluate(()=>window.copiedConnection),issued.urls.global);assert.equal(downloads.length+qrRequests.length,0,'copy does not download or create QR');
   await p.locator('[data-xc-act=qr-sub]').click();assert.equal(await decodeQr(p.locator('.xc-qr').first()),issued.urls.global);assert.match(await p.locator('.xc-caption').first().innerText(),lang==='zh'?/訂閱網址/:/subscription URL/);
   // A late QR response for an older selection must never appear (shared generation guard).
   let release;const gate=new Promise(r=>release=r);await p.route('**/api/v1/qr',async route=>{await gate;await route.continue()});
   await p.locator('[data-xc-act=qr-sub]').click();await radio(p,'profile','internal');release();await p.waitForTimeout(800);
   assert.equal(await p.locator('.xc-qr').count(),0,'stale QR discarded after the selection changed');await p.unroute('**/api/v1/qr');await radio(p,'profile','global');
   await radio(p,'client','singbox');assert.equal(await p.locator('.xc-reveal input[data-xc=format]').count(),2,'sing-box profile type revealed');
   assert.equal(await p.locator('.xc-out input[readonly]').first().inputValue(),issued.exports.global.singbox);
   const endpoints=issued.catalog.endpoints.map(e=>e.id);
   if(endpoints.includes('ipv4')){await p.locator('.xc-more > summary').click();await radio(p,'endpoint','ipv4');assert.match(await p.locator('.xc-out input[readonly]').first().inputValue(),/[?&]endpoint=ipv4$/);await radio(p,'endpoint',endpoints[0]);}
   await radio(p,'format','json');assert.equal(await p.locator('.xc input[data-xc=profile]').count(),0,'basic proxy has no routing choices');
   await radio(p,'method','file');let dl=p.waitForEvent('download');await p.locator('[data-xc-act=download]').click();const socks=await dl;assert.equal(socks.suggestedFilename(),'sbox-global-socks.json');assert.match(fs.readFileSync(await socks.path(),'utf8'),/FIXTURE export .*global, json/);
   await radio(p,'format','singbox');assert.equal(await p.locator('.xc input[data-xc=profile][value=cn]').isDisabled(),false,'China-direct offered in the sing-box complete profile (offline rules)');await radio(p,'profile','internal');dl=p.waitForEvent('download');await p.locator('[data-xc-act=download]').click();assert.equal((await dl).suggestedFilename(),'sbox-internal-sing-box.json');
   await radio(p,'method','nodes');assert.equal(await p.locator('.xc-step:visible').count(),3,'routing step hidden for single-server links');
   await p.locator('[data-xc-act=nodes]').click();await p.locator('.xc-node').first().waitFor();assert.equal(await p.locator('.xc-node').count(),5);
   const first=await p.locator('.xc-node input').first().inputValue();await p.locator('.xc-node [data-xc-act=qr-node]').first().click();assert.equal(await decodeQr(p.locator('.xc-node .xc-qr').first()),first);
   assert.match(await p.locator('.xc-node .xc-caption').first().innerText(),lang==='zh'?/一條伺服器連結/:/one server link/);
   await p.locator('[data-xc-act=copy-node]').first().click();assert.equal(await p.evaluate(()=>window.copiedConnection),first);
   await radio(p,'method','subscription');await radio(p,'client','mihomo');
   // Routing wording reflects the generated rules (no "everything through the VPN" claim).
   const internalLabel=await p.locator('.xc input[data-xc=profile][value=internal] + label').innerText();
   assert.match(internalLabel,lang==='zh'?/包括私人位址/:/including private addresses/);assert.doesNotMatch(await p.locator('.xc').innerText(),/Everything through|全部經 VPN/);
   await p.locator('.xc-why > summary').click();await radio(p,'profile','internal');assert.equal(await p.locator('.xc-why').evaluate(d=>d.open),true,'routing note stays open across re-render');assert.match(await p.locator('.xc-routing-note').innerText(),lang==='zh'?/VPN 伺服器本身/:/VPN server itself is always direct/);await radio(p,'profile','global');
   assert.match(await p.locator('.xc-summary').innerText(),/YAML/,'summary names the configuration type');
   // Background refresh never resets the selection.
   await radio(p,'client','singbox');await radio(p,'profile','internal');const before=await p.locator('.xc').elementHandle();
   await p.evaluate(()=>render({background:true}));await p.waitForTimeout(600);
   assert.equal(await p.locator('.xc input[data-xc=client]:checked').inputValue(),'singbox');assert.equal(await p.locator('.xc input[data-xc=profile]:checked').inputValue(),'internal');
   assert.equal(await before.evaluate(e=>e.isConnected),true,'component not remounted by background refresh');
   await radio(p,'profile','global');await radio(p,'client','mihomo');
   // Link lifecycle lives in a collapsed, labelled section with consequences and a confirmation.
   const manage=p.locator('#modal-body details.manage-subscription');assert.equal(await manage.evaluate(d=>d.open),false,'collapsed while a link is active');
   await manage.locator('summary').click();assert.match(await manage.innerText(),lang==='zh'?/立即失效/:/stop working at once/);
   await manage.locator('[data-action=sub-revoke]').click();await p.locator('#modal-title').filter({hasText:lang==='zh'?'撤銷訂閱連結？':'Revoke subscription link?'}).waitFor();
   assert.equal(await p.locator('#modal-foot [data-action=sub-confirm][data-operation=revoke]').count(),1);
   await p.locator('#modal-foot [data-action=user-share]').click();await p.locator('.xc').waitFor();
   assert.equal(await p.evaluate(async id=>(await(await fetch('/api/v1/subscriptions')).json()).users.find(u=>u.id===id).subscription_active,issued.id),true,'Back cancels without revoking');
  }
  assert.equal(await p.locator('#modal-foot [data-action=sub-revoke], #modal-foot [data-action=sub-rotate]').count(),0,'no link replace/revoke beside Close');
  const g=await geometry(p,width);assert(!g.overflow,'no horizontal overflow');assert.equal(g.outside,0,'controls inside viewport');assert.equal(g.smallButtons,0,'action buttons >= 40px');
  await p.locator('.xc input[data-xc=client]').first().focus();await p.keyboard.press('ArrowDown');assert.equal(await p.evaluate(()=>document.activeElement?.value),'singbox','arrow keys move within the radio group');
  assert.equal(await p.evaluate(()=>{const s=getComputedStyle(document.activeElement);return s.outlineStyle!=='none'&&parseFloat(s.outlineWidth)>=2}),true,'visible focus');
  await radio(p,'client','mihomo');
  await p.screenshot({path:path.join(out,`admin-export-${lang}-${theme}-${width}.png`),fullPage:false});
  landing=issued.page;  // each context rotates the link; older tokens are revoked
  if(landing&&(width===390||width===1440)){
   const lp=await c.newPage();lp.on('pageerror',e=>errors.push('landing: '+e.message));await lp.goto(landing+'?lang='+lang);await lp.locator('.xc').waitFor();
   const subUrl=await lp.locator('.xc-out input[readonly]').first().inputValue();assert.equal(subUrl,landing+'global.yaml');
   await lp.locator('[data-xc-act=qr-sub]').click();assert.equal(await decodeQr(lp.locator('.xc-qr').first()),subUrl,'landing QR encodes its own subscription URL');
   await radio(lp,'method','nodes');await lp.locator('[data-xc-act=nodes]').click();await lp.locator('.xc-node').first().waitFor();assert.equal(await lp.locator('.xc-node').count(),5);
   await lp.locator('.xc-node [data-xc-act=qr-node]').nth(2).click();assert.match(await decodeQr(lp.locator('.xc-node .xc-qr').first()),/^hysteria2:\/\//);
   const lg=await geometry(lp,width);assert(!lg.overflow);await lp.screenshot({path:path.join(out,`landing-${lang}-${theme}-${width}.png`),fullPage:true});await lp.close();
  }
  assert.deepEqual(errors,[]);rows.push({lang,theme,width,status:'PASS',full,fixture:true});await c.close();
 }
 fs.writeFileSync(path.join(out,'browser-results.json'),JSON.stringify({fixture:true,scope:'actual HTTPS admin + landing Export Center; synthetic users',rows},null,2));console.log(JSON.stringify({status:'PASS',cases:rows.length,fixture:true}));
})().catch(e=>{fs.writeFileSync(path.join(out,'failure.json'),JSON.stringify({error:e.message,rows},null,2));console.error(e.stack);process.exitCode=1}).finally(async()=>{if(browser)await browser.close();if(fixture)fixture.kill('SIGTERM')});
