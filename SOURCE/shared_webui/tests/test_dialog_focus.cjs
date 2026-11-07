/* Browser disabling a focused trigger blurs it before asynchronous work opens
   the dialog. Exercise the actual shared helpers and focus return target. */
const fs=require('fs'),path=require('path'),vm=require('vm'),assert=require('assert/strict');
function setup(){
 const body={tagName:'BODY',focus(){}},nodes={},document={activeElement:body,body,documentElement:{},contains:el=>el?.connected!==false};
 function node(id){return nodes[id]??=( {id,connected:true,open:false,dataset:{},textContent:'Open',classList:{remove(){}},setAttribute(){},removeAttribute(){},replaceChildren(){},focus(){document.activeElement=this},showModal(){this.open=true},close(){this.open=false}} );}
 const trigger=node('#trigger');Object.defineProperty(trigger,'disabled',{get(){return !!this._disabled},set(v){this._disabled=v;if(v&&document.activeElement===this)document.activeElement=body}});
 const context={document,state:{gen:1},inflight:new Set(),$:node,$$:()=>[],applyWidths(){},initializePlanFields(){},URL:{revokeObjectURL(){}},setInterval:()=>1,clearInterval(){},setTimeout(){},console};vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../frontend-src/js/01-api.js'),'utf8'),context);return{context,nodes,trigger,document,run:code=>vm.runInContext(code,context)};
}
(async()=>{
 let t=setup();t.trigger.focus();await t.run("guarded('open',$('#trigger'),async()=>{await Promise.resolve();modal('Details','A form')})");assert.equal(t.run('modalOpener'),t.trigger,'Async dialog must retain its disabled original trigger');t.run('closeModal();onModalClosed()');assert.equal(t.document.activeElement,t.trigger,'Closing returns keyboard focus to the original control');
 t=setup();t.trigger.focus();await t.run("guarded('read',$('#trigger'),async()=>{await Promise.resolve()})");assert.equal(t.run('modalOpener'),null,'Non-dialog actions must not leave a stale opener');
 t=setup();t.trigger.focus();t.run("modal('First','Body')");const original=t.run('modalOpener');await t.run("guarded('next',$('#inside'),async()=>{modal('Review','Second step')})");assert.equal(t.run('modalOpener'),original,'Replacing an open dialog retains the first outside trigger');t.run('closeModal();onModalClosed()');assert.equal(t.document.activeElement,t.trigger);
 t=setup();t.trigger.focus();t.run("modal('Details','Body')");t.trigger.connected=false;t.run('closeModal();onModalClosed()');assert.equal(t.document.activeElement,t.nodes['#title'],'If a refreshed page removes the trigger, return focus to its heading');
 console.log('Dialog focus: async trigger, non-dialog cleanup, replacement, removed trigger — 4 passed');
})().catch(e=>{console.error(e);process.exitCode=1});
