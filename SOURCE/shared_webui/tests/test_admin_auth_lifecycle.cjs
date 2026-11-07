/* Exact API/shell/login handlers with deferred HTTP responses. Constructed
   responses are unit evidence, not live authentication or VPN acceptance. */
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=name=>fs.readFileSync(path.join(__dirname,'../frontend-src/js',name),'utf8');
const deferred=()=>{let resolve;const promise=new Promise(r=>{resolve=r});return {promise,resolve}};
const flush=()=>new Promise(r=>setImmediate(r));
function response(body,status=200,text){return {ok:status<400,status,statusText:status===401?'Unauthorized':'OK',headers:{get:name=>name==='Content-Type'?'application/json':null},text:text||(()=>Promise.resolve(JSON.stringify(body)))}}
const account=(name='new-account')=>({schema:1,name,role:'admin',reset:false,csrf:'current-csrf',version:'unit-test'});
function setup(){
  const elements=new Map(),requests=[];
  const node=()=>({hidden:false,open:false,textContent:'',innerHTML:'',dataset:{},setAttribute(){},removeAttribute(){},focus(){},blur(){},close(){this.open=false},replaceChildren(){this.innerHTML=''},contains(){return false},classList:{remove(){}}});
  const $=selector=>{if(!elements.has(selector))elements.set(selector,node());return elements.get(selector)};
  $('#shell').hidden=true;
  const form={fields:{username:'SYNTHETIC-admin',password:'SYNTHETIC-unit-password',code:''},elements:{username:{value:''}},reset(){for(const key of Object.keys(this.fields))this.fields[key]=''}};
  class FormData{constructor(form){this.fields=form.fields}*[Symbol.iterator](){yield*Object.entries(this.fields)}}
  const state={gen:0,me:null,csrf:'',lang:'en',theme:'light',userView:{selected:new Set()}};
  const document={body:node(),documentElement:{dataset:{}},activeElement:null,contains(){return true},querySelector:$,querySelectorAll:()=>[]};
  const context={submitNetwork:async()=>{},state,document,$,$$:()=>[],bi:en=>en,esc:String,FormData,AbortSignal,URL,Blob,console,setTimeout,clearTimeout,setInterval,clearInterval,window:{scrollTo(){}},location:{hash:''}};
  context.fetch=async(url,options)=>{const route=url.replace('/api/v1/','');requests.push({route,options,gen:state.gen});return context.router(route,options)};
  context.router=async route=>response(route==='auth/me'?account():route==='auth/login'?{csrf:'login-csrf'}:{variant:'universal'});
  vm.createContext(context);vm.runInContext(source('01-api.js'),context);vm.runInContext(source('10-shell.js'),context);
  const events=source('90-events.js'),boundary='\ndocument.documentElement.dataset.theme =';
  assert.ok(events.includes(boundary),'event bootstrap boundary must remain explicit');
  vm.runInContext(events.slice(0,events.indexOf(boundary)),context);
  // Authentication state and controls are real handlers; unrelated dashboard rendering is outside this unit's scope.
  vm.runInContext('render=async()=>{};refreshAlertCount=()=>{}',context);
  const forms=vm.runInContext('forms',context);
  return {state,form,requests,context,$,run:code=>vm.runInContext(code,context),login:()=>forms['login-form'](form),
    snapshot:()=>({gen:state.gen,name:state.me?.name||null,csrf:state.csrf,shellHidden:$('#shell').hidden,authHidden:$('#auth').hidden,error:$('#auth-error').textContent})};
}
const tests={
  async 'anonymous startup 401 during a successful login cannot cancel that login'(){
    const e=setup(),initial=deferred(),login=deferred();let reads=0;
    e.context.router=route=>route==='auth/me'&&++reads===1?initial.promise:route==='auth/login'?login.promise:Promise.resolve(response(route==='auth/me'?account():{variant:'universal'}));
    const startup=e.run('initialize()').catch(error=>error),pending=e.login();
    initial.resolve(response({error:'Not signed in'},401));await startup;
    login.resolve(response({csrf:'login-csrf'}));await pending;
    assert.equal(e.state.me?.name,'new-account');assert.equal(e.$('#shell').hidden,false);
    assert.equal(e.$('#auth-error').textContent,'');assert.equal(e.state.csrf,'current-csrf');
  },
  async '401 body delivered after a new login cannot sign the new session out'(){
    const e=setup(),body=deferred();let reads=0;
    e.context.router=route=>Promise.resolve(route==='auth/me'&&++reads===1?response(null,401,()=>body.promise):response(route==='auth/me'?account():route==='auth/login'?{csrf:'login-csrf'}:{variant:'universal'}));
    const startup=e.run('initialize()').catch(error=>error);await flush();
    await e.login();const accepted=e.snapshot();
    body.resolve(JSON.stringify({error:'Obsolete unauthenticated read'}));const discarded=await startup;
    assert.equal(discarded?.stale,true);assert.deepEqual(e.snapshot(),accepted);
    assert.equal(e.$('#shell').hidden,false);
  },
  async 'successful old response body cannot restore a previous account after re-login'(){
    const e=setup(),body=deferred();let reads=0;
    e.context.router=route=>Promise.resolve(route==='auth/me'&&++reads===1?response(null,200,()=>body.promise):response(route==='auth/me'?account():route==='auth/login'?{csrf:'login-csrf'}:{variant:'universal'}));
    const startup=e.run('initialize()').catch(error=>error);await flush();
    e.run("showAuth('Signed out.')");await e.login();const accepted=e.snapshot();
    body.resolve(JSON.stringify(account('old-account')));const discarded=await startup;
    assert.equal(e.state.me.name,'new-account');
    assert.equal(discarded?.stale,true);assert.deepEqual(e.snapshot(),accepted);
  },
  async 'sign-out while login is pending keeps sign-out state without exposing stale errors'(){
    const e=setup(),login=deferred();e.context.router=()=>login.promise;
    const pending=e.login();e.run("showAuth('Signed out.')");
    login.resolve(response({csrf:'obsolete-csrf'}));await pending;
    assert.equal(e.state.me,null);assert.equal(e.state.csrf,'');assert.equal(e.$('#shell').hidden,true);
    assert.equal(e.$('#auth-error').textContent,'Signed out.');
  },
  async 'genuine wrong-password response keeps the friendly login error'(){
    const e=setup();e.context.router=()=>Promise.resolve(response({error:'Denied'},401));await e.login();
    assert.equal(e.$('#auth-error').textContent,'Wrong username, password or code.');
    assert.equal(e.$('#shell').hidden,true);assert.equal(e.state.me,null);
  },
  async 'empty login fields neither cancel startup nor issue a request'(){
    const e=setup();e.form.fields.password='';await e.login();
    assert.equal(e.state.gen,0);assert.equal(e.requests.length,0);
    assert.equal(e.$('#auth-error').textContent,'Enter your username and password.');
  },
  async 'ordinary initial 401 still opens the sign-in view'(){
    const e=setup();e.context.router=()=>Promise.resolve(response({error:'Not signed in'},401));
    const error=await e.run('initialize()').catch(error=>error);
    assert.equal(error.handled,true);assert.equal(e.state.gen,1);assert.equal(e.$('#shell').hidden,true);
    assert.equal(e.$('#auth').hidden,false);
  },
  async 'login retains the same-origin POST and existing CSRF request contract'(){
    const e=setup();e.state.csrf='prior-csrf';await e.login();const req=e.requests.find(row=>row.route==='auth/login');
    assert.equal(req.options.method,'POST');assert.equal(req.options.credentials,'same-origin');
    assert.equal(req.options.cache,'no-store');assert.equal(req.options.headers['X-CSRF-Token'],'prior-csrf');
    assert.deepEqual(JSON.parse(req.options.body),{username:'SYNTHETIC-admin',password:'SYNTHETIC-unit-password',code:''});
    assert.equal(e.state.csrf,'current-csrf');
  },
};
(async()=>{let failed=0;for(const [name,test]of Object.entries(tests)){try{await test();console.log('PASS',name)}catch(error){failed++;console.error('FAIL',name,'\n',error.stack)}}console.log(`${Object.keys(tests).length-failed}/${Object.keys(tests).length} admin auth lifecycle regressions passed; deferred fixtures, NOT live acceptance.`);process.exitCode=failed?1:0})();
