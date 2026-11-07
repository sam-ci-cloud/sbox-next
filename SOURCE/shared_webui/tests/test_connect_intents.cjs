/* Regression for the connection workflow. Synthetic DOM/HTTP, not VPN evidence. */
const assert=require('node:assert/strict'),fs=require('fs'),path=require('path');
const lifecycle=fs.readFileSync(path.join(__dirname,'test_portal_lifecycle.cjs'),'utf8');
const environment=new Function('require','__dirname',lifecycle.split('const tests = {')[0]+'\nreturn environment;')(require,__dirname);
const CATALOG="{schema:1,clients:[{id:'mihomo',formats:[{id:'yaml'}]}],profiles:[{id:'global'}],endpoints:[{id:'auto'},{id:'ipv6'}],methods:[{id:'subscription'}],text:{},files:{},urls:{global:{yaml:'https://vpn.example.test/sub/SYNTHETIC/global.yaml'}},subscription_state:'ready'}";
function withCenter(e){const seen={};e.context.SBOXExportCenter={mount:(host,options)=>{seen.host=host;seen.options=options;return{destroy(){}}}};return seen;}
const tests={
 'connection page hosts the shared Export Center and keeps link management separate'(){
  const e=environment('connection');const seen=withCenter(e);e.run(`connection={recoverable:true,active:true,state:'ready',catalog:${CATALOG}};render()`);
  const html=e.run('connectionPage()');assert.match(html,/id="portal-export"/);assert.match(html,/Manage subscription link/);assert.match(html,/id="replace"/);assert.match(html,/id="revoke"/);
  for(const old of ['vpn-endpoint','subscription-url','advanced-nodes','device-platform'])assert.doesNotMatch(html,new RegExp('id="'+old+'"'),'old portal-only export control remains: '+old);
  e.run('mountPortalExport()');assert.equal(seen.options.catalog.urls.global.yaml,'https://vpn.example.test/sub/SYNTHETIC/global.yaml','component receives the server catalog');
 },
 async 'every adapter call uses this session only (no user id) and the selected choices'(){
  const e=environment('connection');const seen=withCenter(e);e.route(route=>({ok:true,status:200,json:async()=>(route==='me/export'?{content:'vless://a@b:1#x\nnot-a-node\n'}:{svg:'<svg/>'})}));
  e.run(`connection={recoverable:true,active:true,state:'ready',catalog:${CATALOG}};render();mountPortalExport()`);const a=seen.options.adapter,sel={client:'singbox',format:'singbox',profile:'cn',endpoint:'ipv6',method:'file'};
  await a.download(sel);await a.nodes(sel);await a.qrSubscription(sel,'ignored');await a.qrNode(sel,2,'ignored');
  assert.deepEqual(e.calls.map(c=>c.route),['me/export','me/export','me/qr','me/node-qr']);
  const bodies=e.calls.map(c=>JSON.parse(c.options.body));
  assert.deepEqual(bodies[0],{profile:'cn',format:'singbox',endpoint:'ipv6'});assert.equal(bodies[1].format,'links');assert.deepEqual(bodies[3],{profile:'cn',index:2,endpoint:'ipv6'});
  for(const b of bodies)assert.ok(!('id' in b)&&!('user' in b),'portal never sends a user identity');
 },
 'node list keeps protocol URIs only'(){const e=environment('connection');assert.deepEqual(JSON.parse(JSON.stringify(e.run("protocolUris('vless://a\\nhttp://x\\ntuic://b\\n')"))),['vless://a','tuic://b']);},
 'unrecoverable links explain the next step and still mount file/node export'(){
  for(const [state,text] of [['legacy','cannot show it'],['key_unavailable','restore the matching private backup']]){const e=environment('connection');const seen=withCenter(e);e.run(`connection={recoverable:false,active:true,state:'${state}',catalog:${CATALOG}};render()`);assert.match(e.run('connectionPage()'),new RegExp(text,'i'));e.run('mountPortalExport()');assert.ok(seen.options,'export still available for '+state);}
 },
 'Chinese labels remain escaped'(){
  const e=environment('connection');withCenter(e);e.run(`lang='zh';connection={recoverable:true,active:true,state:'ready',catalog:${CATALOG}};render()`);
  const html=e.run('connectionPage()');for(const label of ['連線與匯出','管理訂閱連結','隱藏私人資料'])assert.ok(html.includes(label),label);
  assert.doesNotMatch(html,/<script/i);
 }
};
(async()=>{let failed=0;for(const [name,test] of Object.entries(tests)){try{await test();console.log(JSON.stringify({name,status:'PASS',fixture:true}))}catch(e){failed++;console.log(JSON.stringify({name,status:'FAIL',error:e.message,fixture:true}))}}process.exitCode=failed?1:0})()
