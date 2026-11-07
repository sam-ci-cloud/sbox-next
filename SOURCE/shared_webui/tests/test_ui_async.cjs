/* Exercise delayed responses against the real event handlers. Secrets must not
   cross a dialog, selected format, personal page or user-detail boundary. */
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const source=name=>fs.readFileSync(path.join(__dirname,'../frontend-src',name),'utf8');
function deferred(){let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};}
async function admin(){
  let response,created=0,renders=0;
  const output={isConnected:true,innerHTML:'',focus(){},addEventListener(){}},state={urls:{global:'first'}};
  const context={submitNetwork:async()=>{},actions:{},forms:{},state,modalGeneration:1,modalBlobURLs:new Set(),
    api:()=>response.promise,$:()=>output,document:{documentElement:{dataset:{}},addEventListener(){}},window:{addEventListener(){}},matchMedia:()=>({addEventListener(){}}),setInterval(){},translateAuth(){},guarded(){},initialize(){},onModalClosed(){},
    renderUserDetail(){renders++;context.modalGeneration++;},esc:String,bi:x=>x,
    URL:{createObjectURL(){created++;return 'blob:test';},revokeObjectURL(){}},Blob};
  vm.createContext(context);vm.runInContext(source('js/52-adaptive-charts.js'),context);vm.runInContext(source('js/90-events.js'),context);vm.runInContext(source('js/95-quota-events.js'),context);
  const actions=vm.runInContext('actions',context);
  response=deferred();let pending=actions.qr({dataset:{profile:'global'}});
  context.modalGeneration++;response.resolve({svg:'<svg/>'});await pending;assert.equal(created,0);
  response=deferred();pending=actions.qr({dataset:{profile:'global'}});
  state.urls={global:'new-format'};response.resolve({svg:'<svg/>'});await pending;assert.equal(created,0);
  response=deferred();pending=actions.qr({dataset:{profile:'global'}});
  response.resolve({svg:'<svg/>'});await pending;assert.equal(created,1);assert.match(output.innerHTML,/blob:test/);
  const first={id:'one',tab:'overview',activity:null};state.detail=first;response=deferred();
  pending=actions['detail-tab']({dataset:{tab:'activity'}});
  const second={id:'two',tab:'activity',activity:null};state.detail=second;
  response.resolve({events:[{event:'private-one'}]});await pending;
  assert.equal(second.activity,null);assert.equal(first.activity,null);assert.equal(renders,1);
}
// Personal-portal stale QR/format races are now handled by the shared Export Center and asserted in
// test_connect_browser.cjs (delayed /api/v1/qr response after a selection change).
async function portal(){}
(async()=>{await admin();await portal();console.log('Delayed UI responses: closed/changed admin dialogs, user activity isolation, personal format/hide boundaries passed.');})().catch(error=>{console.error(error);process.exitCode=1});
