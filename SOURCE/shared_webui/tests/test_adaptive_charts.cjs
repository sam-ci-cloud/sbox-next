/* Pure geometry checks complement the required real-browser pixel assertions. */
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const context={esc:s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),bi:s=>s,bitrate:n=>n+' bit/s',when:t=>'time '+t,locale:()=> 'en-GB'};
vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../frontend-src/js/52-adaptive-charts.js'),'utf8'),context);
const render=(points,width=280)=>context.adaptiveChartSvg({keys:['rx_bps','tx_bps'],points,start:100,end:200,window_seconds:100,label:'Traffic'},width);
for(const width of [160,248,316,700,1100]){
 const out=render([{t:120,rx_bps:100,tx_bps:0},{t:160,rx_bps:0,tx_bps:80}],width);
 assert.match(out,new RegExp('viewBox="0 0 '+width+' 240"'));
 assert.match(out,/width="\d+" height="240"/);assert.ok(!/NaN|Infinity|undefined/.test(out));
 const labels=[...out.matchAll(/class="axis" x="([\d.]+)"/g)].map(m=>Number(m[1]));assert.ok(labels.every(x=>x>=0&&x<=width));
}
assert.match(render([]),/No measurements/);
const single=render([{t:150,rx_bps:10,tx_bps:20}]);assert.equal((single.match(/<circle/g)||[]).length,2);assert.ok(!single.includes('<polyline'));
const gap=render([{t:110,rx_bps:1,tx_bps:1},{t:120,rx_bps:2,tx_bps:2},{t:140,gap:true},{t:150,rx_bps:3,tx_bps:3},{t:160,rx_bps:4,tx_bps:4}]);assert.equal((gap.match(/<polyline/g)||[]).length,4,'must not connect across missing samples');
const escaped=context.adaptiveChart({label:'<img onerror=alert(1)>',points:[]});assert.ok(!escaped.includes('<img'));
console.log('Adaptive chart: CSS coordinate widths, selected timeline, zero/one-point and gap geometry passed; browser pixel checks remain separate.');
context.pages={};context.state={monitorWindow:'1h'};context.number=x=>String(x);context.adaptiveChart=model=>model;
vm.runInContext(fs.readFileSync(path.join(__dirname,'../frontend-src/js/51-host-monitor.js'),'utf8'),context);
const now=2000000,range={start:now-3600,end:now,window_seconds:3600};
const metric=context.metricChart([{sampled_at:now-200,value:1,uptime_seconds:100},{sampled_at:now-80,value:2,uptime_seconds:220}],x=>x.value,'CPU',String,range);
assert.equal(metric.points.filter(x=>x.gap).length,1,'raw 120-second missing interval must break');assert.equal(metric.start,range.start);assert.equal(metric.end,range.end);
const old=context.metricChart([{sampled_at:now-9*86400,value:1,uptime_seconds:100},{sampled_at:now-9*86400+3600,value:2,uptime_seconds:3700}],x=>x.value,'CPU',String,{start:now-30*86400,end:now,window_seconds:30*86400});
assert.equal(old.points.filter(x=>x.gap).length,0,'normal hourly retention must stay continuous');
context.placeActionMenu({querySelector:()=>({removeAttribute(name){assert.equal(name,'popover')}}),open:false});
console.log('Metric chart: server range bounds, raw gaps, retained hourly cadence and unavailable-popover fallback passed.');
const unavailable=context.metricChart([{sampled_at:now-90,value:10,uptime_seconds:100},{sampled_at:now-60,value:null,uptime_seconds:130},{sampled_at:now-30,value:20,uptime_seconds:160}],x=>x.value,'CPU',String,range);
assert.equal(unavailable.points.filter(x=>x.gap).length,1,'an explicitly unavailable sample must not be interpolated');
