/* Live authenticated WebUI flow on a disposable deployment (run ON the VPS, loopback).
   Usage: SBOX_AUDIT_PASSWORD=old SBOX_NEW_PASSWORD=new node live_login_flow.cjs ORIGIN OUTDIR
   1. log in with the bootstrap password; 2. complete the forced first change;
   3. require the shell and product version; 4. log out; 5. log in with the new
   password; 6. visit every main page and fail on browser errors. */
const {chromium}=require('playwright');const fs=require('fs');const path=require('path');
const [origin,out]=process.argv.slice(2);const oldPw=process.env.SBOX_AUDIT_PASSWORD;const newPw=process.env.SBOX_NEW_PASSWORD;
if(!origin||!out||!oldPw||!newPw)throw new Error('usage: SBOX_AUDIT_PASSWORD SBOX_NEW_PASSWORD ORIGIN OUTDIR');
fs.mkdirSync(out,{recursive:true});const host=new URL(origin).hostname;const steps=[];const errors=[];
const step=(name,ok,detail='')=>{steps.push({name,ok,detail});if(!ok)throw new Error('FAILED: '+name+' '+detail);};
(async()=>{const browser=await chromium.launch({args:['--host-resolver-rules=MAP '+host+' 127.0.0.1']});
 try{const page=await browser.newPage({viewport:{width:1280,height:900}});
  page.on('pageerror',e=>errors.push(String(e)));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
  const login=async pw=>{await page.goto(origin+'/',{waitUntil:'domcontentloaded'});await page.locator('#login-form input[name=password]').waitFor();
   await page.locator('#login-form input[name=username]').fill('admin');await page.locator('#login-form input[name=password]').fill(pw);await page.locator('#login-submit').click();
   await page.waitForFunction(()=>!document.querySelector('#shell').hidden||!document.querySelector('#password-form').hidden,null,{timeout:30000});};
  await login(oldPw);
  if(await page.locator('#password-form').isVisible()){
   await page.locator('#password-form input[name=old]').fill(oldPw);await page.locator('#password-form input[name=password]').fill(newPw);await page.locator('#pw-confirm').fill(newPw);await page.locator('#pw-submit').click();
   await page.locator('#shell').waitFor({state:'visible',timeout:30000});step('forced initial password change',true);
  } else step('login (password already changed)',await page.locator('#shell').isVisible());
  const body=await page.textContent('body');step('product version shown',/1\.2\.\d/.test(body),(body.match(/1\.2\.\d[^\s]*/)||[''])[0]);
  await page.screenshot({path:path.join(out,'after-login.png')});
  await page.context().clearCookies();await login(newPw);step('re-login with the new password',await page.locator('#shell').isVisible());
  // Anonymous session probes before login answer 401 by design; judge only the authenticated session.
  errors.length=0;
  for(const p of ['overview','users','subscriptions','traffic','security','certificates','updates','settings']){await page.goto(origin+'/#'+p,{waitUntil:'domcontentloaded'});await page.waitForTimeout(1500);await page.screenshot({path:path.join(out,'page-'+p+'.png')});step('page '+p,await page.locator('#shell').isVisible());}
  step('no browser errors',errors.length===0,errors.slice(0,3).join(' | '));
 }finally{fs.writeFileSync(path.join(out,'live-login-flow.json'),JSON.stringify({origin,steps,errors},null,1));await browser.close();}
})().then(()=>console.log('PASS live login flow'),e=>{console.error(String(e));process.exit(1);});
