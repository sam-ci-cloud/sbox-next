const assert=require('assert/strict'),fs=require('fs'),vm=require('vm'),path=require('path');
const state={lang:'en',timezoneData:{timezones:['UTC','Asia/Hong_Kong','America/New_York'],countries:{}}},context={state,bi:(en)=>en,locale:()=> 'en-GB',esc:x=>String(x).replaceAll('"','&quot;'),document:{},Intl,checkbox:(name,label,checked)=>`<label><input type="checkbox" name="${name}" ${checked?'checked':''}>${label}</label>`,select:(name,label,options,value)=>`<select name="${name}">${options.map(([v])=>`<option value="${v}" ${v===value?'selected':''}>${v}</option>`).join('')}</select>`,field:()=>''};
vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../frontend-src/js/33-quota.js'),'utf8'),context);
for(const n of [0,100000000000,107374182400,1250000000,536870912,999999999999999]){const result=vm.runInContext('quotaDisplay('+n+')',context);if(n)assert.equal(Number(result.amount)*({B:1,KB:1000,KiB:1024,MB:1e6,MiB:1048576,GB:1e9,GiB:1073741824,TB:1e12,TiB:1099511627776}[result.unit]),n);}
assert.equal(vm.runInContext('quotaDisplay(100000000000).unit',context),'GB');assert.equal(vm.runInContext('quotaDisplay(107374182400).unit',context),'GiB');
assert.equal(vm.runInContext("localDateTime(1793462400,'Asia/Hong_Kong')",context),'2026-11-01T00:00');
const input=vm.runInContext("planInput({amount:'100',unit:'GiB',unlimited:'on',period:'monthly',timezone:'Asia/Hong_Kong',reset_day:'31',no_expiry:'on'})",context);assert.equal(input.unlimited,true);assert.equal(input.no_expiry,true);assert.equal(input.reset_day,31);assert.equal(input.amount,'100');
assert.doesNotThrow(()=>vm.runInContext('quotaFields(null)',context));
const quotaHtml=vm.runInContext("quotaFields({quota_bytes: 107374182400, timezone:'Asia/Hong_Kong'})",context);
assert.match(quotaHtml,/name="unlimited"|Unlimited data/, 'unlimited checkbox remains');
assert.match(quotaHtml,/<select name="unit">/, 'one native scrollable unit selector');
assert.match(quotaHtml,/<option value="GiB" selected>/, 'saved binary unit remains selected');
assert.doesNotMatch(quotaHtml,/data-plan-preset|class="unit-more"|type="radio"/, 'remove preset and radio clutter');
assert.deepEqual(Array.from(quotaHtml.matchAll(/<option value="(B|KB|KiB|MB|MiB|GB|GiB|TB|TiB)"/g),m=>m[1]).sort(),['B','GB','GiB','KB','KiB','MB','MiB','TB','TiB'].sort());

console.log('Plan form: canonical units round-trip, Hong Kong local datetime and payload modes passed.');
