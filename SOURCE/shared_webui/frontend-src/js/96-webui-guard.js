/* WebUI login protection is separate from SSH protection and VPN credentials. */
function webuiGuardCard(d) {
  d=d||{};
  const words={ok:bi('Matches owned configuration','符合專屬設定'),active:bi('Active','運作中'),inactive:bi('Stopped','已停止'),failed:bi('Failed','啟動失敗'),unavailable:bi('Unavailable','無法使用'),missing:bi('Missing','缺少'),unsafe:bi('Foreign or unsafe configuration','非專屬或不安全設定'),drift:bi('Needs repair','需要修復'),configured:bi('Configured locally','已在本機設定'),ready:bi('Owned rule and sets observed','已觀測專屬規則同集合'),idle:bi('Created on the first ban','首次封鎖時建立'),unknown:bi('Unknown','未知')};
  const tag=(component,good)=>{const key=component?.status||'unknown';return status(good.includes(key)?'ok':['unknown','idle'].includes(key)?'unknown':'warning',words[key]||words.unknown)};
  const knownBans=d.bans?.status==='available',addresses=knownBans?d.bans.addresses:[],localReady=d.status==='ok'&&d.configuration?.status==='ok'&&d.service?.status==='active'&&d.jail?.status==='active'&&d.action?.status==='configured'&&['ready','idle'].includes(d.kernel?.status);
  return `<section class="panel mt" id="webui-guard-card" aria-labelledby="webui-guard-title"><div class="section-title"><h2 id="webui-guard-title">${esc(bi('SBOX login protection','SBOX 登入防護'))}</h2>${btn('webui-guard-refresh',bi('Refresh protection status','重新檢查防護'),'ghost','id="webui-guard-refresh"')}</div>
    <p>${status(localReady?'ok':'warning',localReady?bi('Local checks ready','本機檢查已就緒'):bi('Protection needs attention','防護需要留意'))}</p>
    <p class="muted">${esc(bi('Protects administrator and personal portal login on the management HTTPS port only. It does not cover VPN authentication or SSH.','只保護管理 HTTPS 連接埠的管理員及個人入口登入，不涵蓋 VPN 認證或 SSH。'))}</p>
    <dl class="kv"><dt>${esc(bi('Fail2Ban service','Fail2Ban 服務'))}</dt><dd>${tag(d.service,['active'])}</dd>
      <dt>${esc(bi('Owned jail and filter files','專屬 jail 同篩選檔'))}</dt><dd>${tag(d.configuration,['ok'])}</dd>
      <dt>${esc(bi('WebUI jail','WebUI jail'))}</dt><dd>${tag(d.jail,['active'])} <code>sbox-webui</code></dd>
      <dt>${esc(bi('Configured kernel action','已設定的核心封鎖動作'))}</dt><dd>${tag(d.action,['configured'])} · TCP ${esc(d.port??'—')} · nftables</dd>
      <dt>${esc(bi('Observed kernel state','已觀測核心狀態'))}</dt><dd>${tag(d.kernel,['ready'])}${d.kernel?.status==='idle'?`<p class="small muted">${esc(bi('Fail2Ban creates its kernel table on the first ban. No current ban is recorded.','Fail2Ban 在首次封鎖時才建立核心表，目前未記錄封鎖。'))}</p>`:''}</dd>
      <dt>${esc(bi('Network enforcement verification','網絡封鎖驗證'))}</dt><dd>${status('unknown',bi('Unknown · independent verification required','未知 · 需要獨立驗證'))}</dd></dl>
    ${Number.isInteger(d.jail?.maxretry)&&Number.isInteger(d.jail?.findtime)&&Number.isInteger(d.jail?.bantime)?`<p class="small muted">${esc(bi(`${d.jail.maxretry} failed attempts within ${d.jail.findtime} seconds; ban duration ${d.jail.bantime} seconds.`,`${d.jail.findtime} 秒內 ${d.jail.maxretry} 次登入失敗；封鎖 ${d.jail.bantime} 秒。`))}</p>`:''}
    <p class="source">${esc(bi('This view reads local service, jail, action and nftables state. It cannot prove every remote network path.','此畫面讀取本機服務、jail、封鎖動作同 nftables 狀態，無法證明每條外部網絡路徑。'))}${d.sampled_at?' · '+esc(when(d.sampled_at)):''}</p>
    <h3>${esc(bi('WebUI banned addresses','WebUI 已封鎖位址'))}</h3>
    ${knownBans?(addresses.length?`<ul class="plain">${addresses.map(ip=>`<li><code>${esc(ip)}</code>${isAdmin()?btn('webui-guard-unban',bi('Unban from WebUI','解除 WebUI 封鎖'),'ghost',`data-ip="${esc(ip)}" aria-label="${esc(bi('Unban WebUI address ','解除 WebUI 位址封鎖：')+ip)}"`):''}</li>`).join('')}</ul>`:`<p class="muted">${esc(bi('No current bans in this jail.','此 jail 目前沒有封鎖紀錄。'))}</p>`):`<p class="notice warning">${esc(bi('Ban list unavailable. This does not mean that no addresses are banned.','暫時無法讀取封鎖清單，並不代表沒有位址被封鎖。'))}</p>`}
    ${d.kernel?.missing_bans?.length?`<p class="notice warning">${esc(bi('Some jail bans were not found in the owned kernel sets. Repair and verify remotely.','部分 jail 封鎖未見於專屬核心集合，請修復後由外部驗證。'))}</p>`:''}
    ${isAdmin()?`<div class="actions mt" data-admin>${btn('webui-guard-repair',bi('Repair WebUI login protection…','修復 WebUI 登入防護…'))}</div><p class="small muted">${esc(bi('Repairs only the owned WebUI jail and filter using the distribution nftables action. Foreign configuration is retained.','只修復專屬 WebUI jail 及篩選檔，使用發行版的 nftables 動作，保留其他設定。'))}</p>`:''}
  </section>`;
}

async function refreshWebuiGuard() {
  let data;
  try{data=await api('security/webui-guard');}
  catch(error){if(!error.stale&&!error.handled&&state.page==='security'&&$('#webui-guard-card'))$('#webui-guard-card').outerHTML=webuiGuardCard(null);throw error;}
  const target=$('#webui-guard-card');
  if(state.page==='security'&&target){const focused=target.contains(document.activeElement);target.outerHTML=webuiGuardCard(data);if(focused)$('#webui-guard-refresh')?.focus({preventScroll:true});}
}

Object.assign(actions,{
  'webui-guard-refresh':refreshWebuiGuard,
  'webui-guard-repair':()=>modal(bi('Repair WebUI login protection','修復 WebUI 登入防護'),`<p>${esc(bi('Reapply the owned WebUI jail and filter and reload only this jail. Fail2Ban may be started if it is stopped. VPN identities, SSH protection and foreign configuration are retained.','重新套用專屬 WebUI jail 同篩選檔，並只重新載入此 jail。如 Fail2Ban 已停止，會嘗試啟動。保留 VPN 身分、SSH 防護及其他設定。'))}</p>`,`<button type="button" data-close>${esc(bi('Cancel','取消'))}</button>${btn('webui-guard-confirm-repair',bi('Repair login protection','修復登入防護'),'primary')}`),
  'webui-guard-unban':el=>modal(bi('Unban this WebUI address?','解除此 WebUI 位址封鎖？'),`<p><code>${esc(el.dataset.ip)}</code></p><p>${esc(bi('Remove this address from the WebUI jail only. SSH bans stay as they are.','只解除此位址的 WebUI jail 封鎖，保留 SSH 封鎖。'))}</p>`,`<button type="button" data-close>${esc(bi('Cancel','取消'))}</button>${btn('webui-guard-confirm-unban',bi('Unban from WebUI','解除 WebUI 封鎖'),'primary',`data-ip="${esc(el.dataset.ip)}"`)}`),
  'webui-guard-confirm-repair':async()=>{await api('actions',{action:'webui-guard-repair',arguments:{}});closeModal();toast(bi('WebUI repair completed','WebUI 修復已完成'),bi('Review the local checks and verify remotely.','請檢查本機狀態，並由外部驗證。'));await refreshWebuiGuard();},
  'webui-guard-confirm-unban':async el=>{await api('actions',{action:'webui-guard-unban',arguments:{ip:el.dataset.ip}});closeModal();toast(bi('WebUI unban requested','已執行 WebUI 解除封鎖'),bi('Refresh and check the jail and kernel state.','請重新檢查 jail 同核心狀態。'));await refreshWebuiGuard();}
});
