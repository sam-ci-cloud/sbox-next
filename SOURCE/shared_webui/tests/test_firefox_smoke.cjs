/* FIXTURE ONLY: actual Firefox layout/plan controls, not VPN/TLS acceptance. */
const {firefox}=require('playwright'),{spawn}=require('child_process'),fs=require('fs'),path=require('path'),os=require('os'),assert=require('assert/strict');
const root=path.resolve(__dirname,'..'),work=fs.mkdtempSync(path.join(os.tmpdir(),'sbox-firefox-')),port=24000+Math.floor(Math.random()*1000),origin=`https://localhost:${port}`;
(async()=>{
 const child=spawn('python3',[path.join(root,'tests/dev_panel.py'),'--host','localhost','--port',String(port),'--work',work,'--users','4'],{stdio:['ignore','pipe','inherit']});let browser;
 try{
  const info=await new Promise((resolve,reject)=>{let buf='';child.stdout.on('data',d=>{buf+=d;if(buf.includes('\n'))resolve(JSON.parse(buf.split('\n')[0]));});child.on('exit',c=>reject(Error('fixture exited '+c)));});
  browser=await firefox.launch();const context=await browser.newContext({ignoreHTTPSErrors:true});const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(origin);await page.locator('#login-form input[name=username]').fill('admin');await page.locator('#login-form input[name=password]').fill(info.password);await page.locator('#login-submit').click();await page.locator('#shell').waitFor({state:'visible'});
  const out=path.join(root,'../.build/firefox-fixture');fs.mkdirSync(out,{recursive:true});let checked=0;
  for(const width of [320,390,768,1280,2560]){
   await page.setViewportSize({width,height:900});await page.goto(origin+'/#users');await page.locator('[data-action=user-create]').first().click();await page.locator('#new-user-wizard input[name=name]').fill('firefox-'+width);await page.locator('#modal [data-action=wizard-next]').click();
   const form=page.locator('#modal');await form.getByRole('checkbox',{name:'Unlimited data',exact:true}).uncheck();await form.getByRole('spinbutton',{name:'Data allowance',exact:true}).fill('1.5');await form.getByRole('combobox',{name:'Unit',exact:true}).selectOption({label:'GiB'});
   assert.equal(await form.getByRole('combobox',{name:'Unit',exact:true}).locator('option').count(),9);
   const zone=form.getByRole('combobox',{name:'Resets and the end date use this time zone',exact:true});await zone.fill('Tokyo');await page.getByRole('option',{name:/Tokyo/}).click();
   await form.locator('.plan-preview .plan-summary').waitFor();assert.match(await form.innerText(),/1\.5 GiB/);
   const bounds=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,modal:document.querySelector('#modal').getBoundingClientRect().width}));assert(bounds.scroll<=width+1&&bounds.modal<=width);
   await page.screenshot({path:path.join(out,'quota-'+width+'.png')});await page.getByRole('button',{name:'Close dialog',exact:true}).click();checked++;
  }
  assert.equal(checked,5);assert.deepEqual(errors,[]);console.log('PASS Firefox fixture: '+checked+' viewport, quota, unit and timezone cases');
 }finally{if(browser)await browser.close();child.kill('SIGTERM');fs.rmSync(work,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
