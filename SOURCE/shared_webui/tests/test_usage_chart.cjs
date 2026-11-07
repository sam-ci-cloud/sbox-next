/* Geometry and output-encoding regressions; real browser journeys are separate. */
const assert=require('assert/strict'),fs=require('fs'),vm=require('vm'),path=require('path');
const context={window:{},document:{addEventListener(){}}};
vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../frontend-src/shared/usage.js'),'utf8'),context);
const chart=context.window.SBOXUsage;
function data(n){return {window:'24h',timezone:'Asia/Hong_Kong',start:1793116800,end:1793116800+Math.max(n,1)*3600,oldest_date:'2026-07-31',latest_date:'2026-10-28',totals:{upload_bytes:123,download_bytes:456},buckets:Array.from({length:n},(_,i)=>({time:1793116800+i*3600,start:1793116800+i*3600,end:1793116800+(i+1)*3600,up:i===0?123:null,down:i===0?456:null,state:i===0?'partial':'before_collection'})),legacy_utc_daily:[],incomplete:true};}
for(const n of [0,1,2,25,90,169]){const html=chart.render(data(n),'en'),widths=[...html.matchAll(/class="usage-up"[^>]* width="([\d.]+)"/g)].map(x=>Number(x[1]));assert.equal(widths.length,n);assert.ok(widths.every(w=>w<=20&&w>0));assert.equal((html.match(/class="usage-bar"/g)||[]).length,n);assert.ok(!/NaN|Infinity|undefined/.test(html));assert.ok(html.includes('View accessible data table'));if(n===1){const x=Number(html.match(/class="usage-up" x="([\d.]+)"/)[1]);assert.ok(x>200&&x<400,'single bar must be centered and narrow');}}
const escaped=chart.picker('"<script>',data(1),'zh');assert.ok(!escaped.includes('<script>'));assert.ok(escaped.includes('&lt;script&gt;'));
const zero=data(1);zero.buckets[0]={...zero.buckets[0],up:0,down:0,state:'recorded'};assert.ok(chart.render(zero).includes('class="usage-zero"'));
console.log('Usage chart: 0/1/2/25/90/169 buckets, bounded centered columns, zero marker and escaped output passed.');
