/* Local shared usage chart. No framework, remote assets or synthetic measurements. */
window.SBOXUsage = (() => {
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const text = (lang, en, zh) => lang === 'zh' ? zh : en;
  const locale = lang => lang === 'zh' ? 'zh-Hant-HK' : 'en-GB';
  const size = (n, lang) => { if (n === null || n === undefined) return '—'; let v=n,i=0;while(v>=1024&&i<4){v/=1024;i++;}return v.toLocaleString(locale(lang),{maximumFractionDigits:i?2:0})+' '+['B','KiB','MiB','GiB','TiB'][i]; };
  const stamp = (n,zone,lang) => new Date(n*1000).toLocaleString(locale(lang),{timeZone:zone,month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',timeZoneName:'short'});
  const states = lang => ({recorded:text(lang,'Recorded','已記錄'),partial:text(lang,'Partial coverage · measured lower bound','部分觀測 · 實測下限'),before_collection:text(lang,'Before local history collection','本地歷史記錄啟用前'),unobserved:text(lang,'Not observed','未觀測')});
  function picker(id, d, lang) {
    const names=[['24h','Last 24 hours','最近 24 小時'],['7d','Last 7 days','最近 7 日'],['30d','Last 30 days','最近 30 日'],['90d','Last 90 days','最近 90 日'],['custom','Custom dates','自選日期']];
    return `<form class="usage-picker" id="${esc(id)}"><label><span>${text(lang,'Time range','時間範圍')}</span><select name="window">${names.map(([v,en,zh])=>`<option value="${v}" ${d.window===v?'selected':''}>${text(lang,en,zh)}</option>`).join('')}</select></label><div class="usage-custom" ${d.window==='custom'?'':'hidden'}><label><span>${text(lang,'From date','開始日期')}</span><input type="date" name="start" min="${d.oldest_date}" max="${d.latest_date}" value="${d.selected_start||d.latest_date}" required></label><label><span>${text(lang,'Through date','結束日期')}</span><input type="date" name="end" min="${d.oldest_date}" max="${d.latest_date}" value="${d.selected_end||d.latest_date}" required></label></div><button type="submit">${text(lang,'Apply range','套用範圍')}</button><span class="usage-zone">${esc(d.timezone)}</span></form>`;
  }
  function params(form) { const f=new FormData(form);const p={window:f.get('window')};if(p.window==='custom'){p.start=f.get('start');p.end=f.get('end');}return p; }
  function render(d, lang='en', opts={}) {
    // Same unit family as the user's plan (GB beside a GB plan, GiB beside a
    // GiB plan); decimal GB when there is no limit. Never mix families silently.
    const limit=opts.limit||null, binary=quotaFamily(limit)==='binary', size=(n,l)=>quotaSize(n,limit,l);
    const unitNote=binary?text(lang,'Units: 1 GiB = 1,073,741,824 bytes','單位：1 GiB = 1,073,741,824 位元組'):text(lang,'Units: 1 GB = 1,000,000,000 bytes','單位：1 GB = 1,000,000,000 位元組');
    const buckets=d.buckets||[], names=states(lang), max=Math.max(1,...buckets.map(b=>(b.up||0)+(b.down||0))), slot=560/Math.max(1,buckets.length), w=Math.min(20,slot*.68);
    const title=text(lang,'Measured upload and download over the selected range. Use left and right arrows to inspect each bucket.','所選範圍的實測上傳及下載，可用左右方向鍵查看每個時段。');
    const bars=buckets.map((b,i)=>{
      const x=20+i*slot+(slot-w)/2, u=150*(b.up||0)/max, v=150*(b.down||0)/max;
      const tip=stamp(b.start,d.timezone,lang)+' – '+stamp(b.end,d.timezone,lang)+' · ↑ '+size(b.up,lang)+' · ↓ '+size(b.down,lang)+' · '+names[b.state];
      return `<g class="usage-bar" tabindex="${i===0?0:-1}" role="img" aria-label="${esc(tip)}" data-tip="${esc(tip)}"><title>${esc(tip)}</title><rect class="usage-hit" x="${20+i*slot}" y="5" width="${slot}" height="177"/><rect class="usage-focus" x="${x-4}" y="5" width="${w+8}" height="177"/><rect class="usage-up" x="${x}" y="${174-u-v}" width="${w}" height="${u}"/><rect class="usage-down" x="${x}" y="${174-v}" width="${w}" height="${v}"/>${b.state!=='recorded'?`<rect class="usage-gap" x="${x}" y="180" width="${Math.max(2,w)}" height="4"/>`:b.up===0&&b.down===0?`<circle class="usage-zero" cx="${x+w/2}" cy="174" r="2"/>`:''}</g>`;
    }).join('');
    const up=d.totals.upload_bytes, down=d.totals.download_bytes;
    const table=rows=>`<div class="usage-table"><table><thead><tr><th scope="col">${text(lang,'Time','時間')}</th><th scope="col">${text(lang,'Upload','上傳')}</th><th scope="col">${text(lang,'Download','下載')}</th><th scope="col">${text(lang,'Coverage','觀測狀態')}</th></tr></thead><tbody>${rows.map(b=>`<tr><th scope="row">${esc(stamp(b.start,d.timezone,lang))}</th><td>${esc(size(b.up,lang))}</td><td>${esc(size(b.down,lang))}</td><td>${esc(names[b.state])}</td></tr>`).join('')}</tbody></table></div>`;
    return `<div class="usage-totals"><div><span>${text(lang,'Selected range · measured total','所選範圍 · 實測總量')}</span><strong>${size(up===null?null:up+down,lang)}</strong></div><div><span>↑ ${text(lang,'Upload','上傳')}</span><strong>${size(up,lang)}</strong></div><div><span>↓ ${text(lang,'Download','下載')}</span><strong>${size(down,lang)}</strong></div></div><div class="usage-legend"><span class="usage-key up">${text(lang,'Upload','上傳')}</span><span class="usage-key down">${text(lang,'Download','下載')}</span><span class="usage-key gap">${text(lang,'Incomplete / missing','不完整／缺漏')}</span><span class="usage-units">${esc(unitNote)}</span></div><div class="usage-plot"><span class="usage-scale">${size(buckets.some(b=>(b.up||0)+(b.down||0)>0)?max:0,lang)}</span><svg viewBox="0 0 600 196" role="group" aria-label="${esc(title)}"><line class="usage-baseline" x1="20" y1="174" x2="580" y2="174"/>${bars}</svg><span class="usage-zero-label">0</span></div><div class="usage-dates"><span>${text(lang,'From','由')} ${esc(stamp(d.start,d.timezone,lang))}</span>${buckets.length>=6?`<span class="usage-mid" aria-hidden="true">${esc(stamp(buckets[Math.floor(buckets.length/2)].start,d.timezone,lang))}</span>`:''}<span>${text(lang,'To','至')} ${esc(stamp(d.end,d.timezone,lang))}</span></div><p class="usage-note">${esc(text(lang,'Selected-range totals are separate from your current quota cycle. Dashes mean no observation; a recorded zero is shown as a point. Partial intervals are measured lower bounds.','所選範圍總量與本期配額用量分開計算。「—」代表沒有觀測；已記錄的零用量會顯示為點。部分時段只顯示實測下限。'))}</p>${d.incomplete?`<p class="usage-notice" role="status">${text(lang,'This range has incomplete history. Data before collection or during gaps is not filled with zero.','此範圍有不完整紀錄。啟用前或計量中斷期間的資料不會以零填補。')}</p>`:''}<details><summary>${text(lang,'View accessible data table','查看資料表')}</summary>${table(buckets)}</details>${d.legacy_utc_daily?.length?`<details><summary>${text(lang,'Earlier measured UTC daily totals','較早的實測 UTC 每日總量')}</summary><p class="usage-note">${text(lang,'These older UTC days cannot be split into local days. The migration day can overlap the chart; do not add the tables.','較早的 UTC 每日彙總無法拆分為本地日。遷移當日可能與圖表重疊，請勿將兩份數據相加。')}</p><div class="usage-table"><table><thead><tr><th>UTC</th><th>↑</th><th>↓</th></tr></thead><tbody>${d.legacy_utc_daily.map(b=>`<tr><th scope="row">${new Date(b.time*1000).toISOString().slice(0,10)}</th><td>${size(b.up,lang)}</td><td>${size(b.down,lang)}</td></tr>`).join('')}</tbody></table></div></details>`:''}`;
  }
  function download(d) {const rows=[['start_utc','end_utc','timezone','upload_bytes','download_bytes','coverage'],...d.buckets.map(b=>[new Date(b.start*1000).toISOString(),new Date(b.end*1000).toISOString(),d.timezone,b.up??'',b.down??'',b.state])];const blob=new Blob([rows.map(row=>row.map(x=>'"'+String(x).replace(/"/g,'""')+'"').join(',')).join('\r\n')],{type:'text/csv;charset=utf-8'});const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='sbox-usage.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  document.addEventListener('change', e=>{if(e.target.matches('.usage-picker select[name=window]')){const form=e.target.form;form.querySelector('.usage-custom').hidden=e.target.value!=='custom';
    // Preset ranges apply immediately; custom dates wait for the Apply button.
    if(e.target.value!=='custom')form.requestSubmit();}});
  let tooltip, tooltipAnchor, tooltipObserver;
  function hideTip() {
    tooltipAnchor=null;tooltipObserver?.disconnect();
    if(tooltip){tooltip.hidden=true;tooltip.textContent='';}
  }
  function placeTip() {
    if(!tooltipAnchor)return;
    const r=(tooltipAnchor.querySelector('.usage-focus')||tooltipAnchor).getBoundingClientRect(),margin=8,gap=8;
    if(!tooltipAnchor.isConnected||!r.width||!r.height||r.bottom<=0||r.top>=innerHeight||r.right<=0||r.left>=innerWidth){hideTip();return;}
    tooltip.style.maxWidth=Math.max(0,Math.min(280,innerWidth-2*margin))+'px';
    tooltip.style.maxHeight=Math.max(0,innerHeight-2*margin)+'px';
    const box=tooltip.getBoundingClientRect(),above=r.top-gap-box.height;
    const top=above>=margin?above:r.bottom+gap;
    tooltip.style.left=Math.max(margin,Math.min(innerWidth-box.width-margin,r.left))+'px';
    tooltip.style.top=Math.max(margin,Math.min(innerHeight-box.height-margin,top))+'px';
  }
  function tip(el) {
    if(!tooltip){tooltip=document.createElement('div');tooltip.className='usage-tooltip';tooltip.setAttribute('role','tooltip');document.body.append(tooltip);}
    // Native dialogs sit above every body z-index. Keep the tooltip in the
    // anchor's top layer so administrator charts remain visible and hoverable.
    const layer=el.closest('dialog[open]')||document.body;
    if(tooltip.parentNode!==layer)layer.append(tooltip);
    tooltipAnchor=el;tooltip.textContent=el.dataset.tip;tooltip.hidden=false;placeTip();
    // A background refresh or session expiry can remove the focused SVG without
    // a focus event. Do not leave its private usage visible on the next page.
    if(tooltipAnchor&&typeof MutationObserver!=='undefined'){
      tooltipObserver??=new MutationObserver(()=>{if(tooltipAnchor&&!tooltipAnchor.isConnected)hideTip();});
      tooltipObserver.observe(document.body,{childList:true,subtree:true});
    }
  }
  document.addEventListener('pointerover', e=>{const el=e.target.closest('.usage-bar');if(el)tip(el);});
  document.addEventListener('pointerout', e=>{
    const el=e.target.closest('.usage-bar'),fromTip=e.target.closest('.usage-tooltip');
    if(!el&&!fromTip)return;
    if(e.relatedTarget?.closest?.('.usage-tooltip')||e.relatedTarget?.closest?.('.usage-bar')===tooltipAnchor)return;
    if(document.activeElement!==tooltipAnchor)hideTip();
  });
  document.addEventListener('focusin',e=>{const el=e.target.closest('.usage-bar');if(el)tip(el);else hideTip();});
  document.addEventListener('pointerdown',e=>{const el=e.target.closest('.usage-bar');if(el)tip(el);else if(!e.target.closest('.usage-tooltip'))hideTip();});
  document.addEventListener('keydown',e=>{if(e.key==='Escape')hideTip();});
  document.addEventListener('close',e=>{if(tooltipAnchor&&e.target.contains(tooltipAnchor))hideTip();},true);
  globalThis.addEventListener?.('resize',placeTip);
  document.addEventListener('scroll',placeTip,true);
  document.addEventListener('keydown',e=>{const el=e.target.closest('.usage-bar');if(!el||!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;e.preventDefault();const bars=[...el.parentNode.querySelectorAll('.usage-bar')];let i=bars.indexOf(el);i=e.key==='Home'?0:e.key==='End'?bars.length-1:Math.max(0,Math.min(bars.length-1,i+(e.key==='ArrowRight'?1:-1)));el.setAttribute('tabindex','-1');bars[i].setAttribute('tabindex','0');bars[i].focus();});
  /* Quota amounts use the same unit family as the plan's own limit, so a
     "500 GB" allowance never reads as "465.7 GiB" beside its own usage bar. */
  const ORDER=[['TB',1e12],['TiB',2**40],['GB',1e9],['GiB',2**30],['MB',1e6],['MiB',2**20],['KB',1e3],['KiB',1024]];
  function quotaFamily(limit){if(!limit)return 'decimal';for(const [u,v] of ORDER){const value=limit/v,s=value.toFixed(6).replace(/\.?0+$/,'');if(value>=1&&Number(s)*v===limit)return u.endsWith('iB')?'binary':'decimal';}return 'decimal';}
  function quotaSize(n,limit,lang){if(n===null||n===undefined)return '—';const binary=quotaFamily(limit)==='binary',base=binary?1024:1000,units=binary?['B','KiB','MiB','GiB','TiB']:['B','KB','MB','GB','TB'];let v=Number(n),i=0;while(Math.abs(v)>=base&&i<units.length-1){v/=base;i++;}return v.toLocaleString(locale(lang),{maximumFractionDigits:i?(Math.abs(v)<10?2:1):0})+' '+units[i];}
  return {render,picker,params,download,size,stamp,quotaSize,quotaFamily};
})();
