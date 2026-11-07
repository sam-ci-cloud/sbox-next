'use strict';
const $=s=>document.querySelector(s), esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const read=(key,fallback)=>{try{return localStorage.getItem(key)||fallback}catch{return fallback}}, save=(key,value)=>{try{localStorage.setItem(key,value)}catch{}};
let lang=read('sbox-portal-lang',(navigator.language||'').startsWith('zh')?'zh':'en'),theme=read('sbox-portal-theme','system'),csrf='',current=null,usage=null,connection=null,page='overview',generation=0,connectionView=0,endpointChoice='auto',historySequence=0,qrUrl=null,usageLoading=false;
const nodeQrUrls=new Set();
function clearNodeQr(){nodeQrUrls.forEach(u=>URL.revokeObjectURL(u));nodeQrUrls.clear();}
let authGeneration=0,refreshSequence=0,refreshTask=null,refreshState='idle',refreshError='',checkedAt=null,historyParams={window:'30d'},historyTask=null,loginAttempt=null;
const DEVICE_NAMES={windows:'Windows',macos:'macOS',linux:'Linux',android:'Android',ios:'iOS'};
const validChoice=(value,choices,fallback)=>choices.includes(value)?value:fallback;
function initialDevice(){const ua=navigator.userAgent||'';return /Android/i.test(ua)?'android':/iPhone|iPad|iPod/i.test(ua)||(/Mac/i.test(ua)&&navigator.maxTouchPoints>1)?'ios':/Mac/i.test(ua)?'macos':/Linux/i.test(ua)?'linux':'windows'}
let device=validChoice(read('sbox-portal-device',initialDevice()),Object.keys(DEVICE_NAMES),'windows');
let profileChoice=validChoice(read('sbox-portal-profile','global'),['global','cn','internal'],'global');
let formatChoice=validChoice(read('sbox-portal-format-'+device,'yaml'),['yaml','json'],'yaml');
const t=(en,zh)=>lang==='zh'?zh:en, size=n=>SBOXUsage.size(n,lang), qsize=n=>SBOXUsage.quotaSize(n,current?.quota_bytes,lang), date=(n,zone=current?.timezone||'UTC')=>n?new Date(n*1000).toLocaleString(lang==='zh'?'zh-Hant-HK':'en-GB',{timeZone:zone,timeZoneName:'short'}):t('None','無');
const labels=()=>({overview:t('Overview','總覽'),usage:t('Usage','用量'),connection:t('Connect Your Device','連接你的裝置'),plan:t('Plan','方案'),account:t('Account','帳戶')});
const statusName=s=>({active:t('Active','可以使用'),manually_disabled:t('Paused','已暫停'),expired:t('Expired','已到期'),quota_exceeded:t('Out of data','數據已用完'),password_change_required:t('Change initial password','請更改初始密碼'),pending_reconciliation:t('Checking allowance','正在核對數據額')}[s]||s);
function message(text=''){$('#message').textContent=text;}
async function api(path,data){
  const sessionVersion=authGeneration;
  const response=await fetch('/api/v1/portal/'+path,{method:data===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',headers:data===undefined?{}:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:data===undefined?undefined:JSON.stringify(data)});
  let value;try{value=await response.json()}catch{value={}}
  if(!response.ok){
    const error=new Error(value?.error||t('Request failed. Please retry.','未能完成請求，請重試。'));error.status=response.status;
    if(response.status===401&&sessionVersion===authGeneration){error.sessionEnded=true;endSession(t('Your session has ended. Sign in again.','工作階段已結束，請重新登入。'))}
    throw error;
  }
  return value;
}
function endSession(text=''){
  authGeneration++;generation++;historySequence++;refreshSequence++;refreshTask=null;historyTask=null;loginAttempt=null;
  checkedAt=null;refreshState='idle';refreshError='';usageLoading=false;historyParams={window:'30d'};
  login();const dialog=$('#confirm-dialog');if(dialog?.open)dialog.close();message(text);
}
function clearConnection(){endpointChoice="auto";clearNodeQr();connectionView++;connection=null;if(qrUrl){URL.revokeObjectURL(qrUrl);qrUrl=null}}
function shell(){document.documentElement.lang=lang==='zh'?'zh-Hant-HK':'en';document.documentElement.dataset.theme=theme==='system'?(matchMedia('(prefers-color-scheme:light)').matches?'light':'dark'):theme;$('#language').textContent=t('繁體中文','English');$('#brand-label').textContent=t('Personal','個人入口');$('#theme').innerHTML=['system','light','dark'].map(x=>`<option value="${x}" ${theme===x?'selected':''}>${({system:t('System','跟隨系統'),light:t('Light','淺色'),dark:t('Dark','深色')})[x]}</option>`).join('');$('#theme').setAttribute('aria-label',t('Appearance','外觀'));$('#footer').textContent=t('SBOX Personal · Your VPN data usage and private connection settings.','SBOX 個人入口 · 查看 VPN 用量，同管理私人連線設定。');}
function login(){current=null;usage=null;csrf='';clearConnection();$('#portal-nav').hidden=true;$('#content').innerHTML=`<section class="card login"><p class="eyebrow">SBOX PERSONAL</p><h1>${t('Your connection, in one place.','連線同用量，一目了然。')}</h1><p class="muted">${t('Sign in to manage your connection and understand your VPN usage.','登入個人帳戶，查看連線設定同 VPN 用量。')}</p><form id="login"><label for="username">${t('Username','使用者名稱')}<input id="username" name="username" autocomplete="username" required maxlength="64"></label><label for="password">${t('Password','密碼')}<input id="password" name="password" type="password" autocomplete="current-password" required maxlength="256"></label><button class="primary" type="submit">${t('Sign in','登入')}</button></form><p class="small">${t('Use your personal portal login supplied by your administrator. It is separate from your VPN credentials.','請使用管理員提供的個人入口登入資料，與 VPN 憑證分開。')}</p></section>`;$('#content').setAttribute('aria-busy','false');$('#login').onsubmit=e=>{e.preventDefault();return signIn(e)};}
function heading(){return `<div class="page-heading"><div><p class="eyebrow">${esc(current.display_name)}</p><h1>${esc(labels()[page])}</h1><p class="muted">${esc(serviceAdvice())}</p><p class="small">${esc(current.expires_at?t('Service ends on ','服務到期：')+date(current.expires_at):t('No expiry set','不設到期時間'))} · ${t('Need help? Contact the administrator who gave you this login.','需要協助？請聯絡提供登入資料的管理員。')}</p></div><div class="actions"><span class="status ${current.status==='active'?'':'warn'}">${esc(statusName(current.status))}</span><button id="refresh" type="button" ${refreshState==='refreshing'?'disabled':''}>${t('Refresh','重新整理')}</button><button id="logout" type="button">${t('Sign out','登出')}</button></div></div>`;}
function refreshMarkup(){
  const last=checkedAt?t('Last account check: ','上次帳戶檢查：')+date(checkedAt):t('Account details have not been checked yet.','尚未檢查帳戶資料。');
  const note=t('Account checks do not confirm a live VPN connection.','帳戶資料檢查並不代表 VPN 現正連線。');
  if(refreshState==='stale')return `${esc(t('Refresh failed. Showing the last available values. ','未能更新，目前顯示上次取得的資料。'))}${esc(last)} ${esc(refreshError)} <button id="retry-refresh" type="button">${t('Retry','重試')}</button> <span class="small">${esc(note)}</span>`;
  return `${refreshState==='refreshing'?esc(t('Checking account and usage… ','正在檢查帳戶同用量… ')):''}${esc(last)} <span class="small">${esc(note)}</span>`;
}
function accountingWarning(){return !current.reset_password&&current.freshness!=='fresh'?`<p class="notice" role="status">${t('Usage updates are delayed. Showing the last recorded amounts; your recent usage may not be included. Use Refresh to check again.','用量更新有延誤。目前顯示上次記錄的數字，可能未計入最近用量。請按「重新整理」再檢查。')}</p>`:'';}
function serviceAdvice(){
  const advice={
    active:t('Your account is ready to use. Connect in your VPN app; this page does not show a live device connection.','帳戶可以使用。請在 VPN app 連線；此頁不會顯示裝置是否正在線上。'),
    manually_disabled:t('Your administrator paused this service. Contact them to resume it.','管理員已暫停服務，請聯絡管理員恢復。'),
    expired:t('Your service has ended. Ask your administrator to renew it.','服務已到期，請聯絡管理員續期。'),
    quota_exceeded:current?.next_reset?t('Your data is used up. Your allowance resets on ','數據已用完，下次重設時間：')+date(current.next_reset):t('Your data is used up. Ask your administrator for more data.','數據已用完，請聯絡管理員增加數據額。'),
    pending_reconciliation:t('We are checking your allowance. Refresh shortly, or contact your administrator if it does not update.','正在核對數據額，請稍後重新整理。如一直未更新，請聯絡管理員。'),
    password_change_required:t('Change your initial password to continue.','請先更改初始密碼，再繼續使用。')};
  return advice[current?.status]||t('Service status is unavailable. Refresh or contact your administrator.','暫時無法確認服務狀態，請重新整理或聯絡管理員。');
}

function overviewExtras(){return `<div class="grid"><section class="card"><h2>${t('Ready to connect?','準備連線？')}</h2><p class="muted">${t('Copy your current subscription, scan a QR or download a profile.','複製現有訂閱、掃描 QR 或下載設定檔。')}</p><button id="go-connect" class="primary" type="button">${t('Open my connection','開啟我的連線')}</button></section><section class="card"><h2>${t('Plan and expiry','方案同到期時間')}</h2><p>${current.expires_at?esc(date(current.expires_at)):t('No expiry set','不設到期時間')}</p><p class="small">${t('Usage updated','用量更新於')} ${esc(date(current.sampled_at))}</p><button id="go-plan" type="button">${t('View plan details','查看方案詳情')}</button></section><section class="card" id="portal-support"><h2>${t('Need help?','需要協助？')}</h2><p>${t('Contact the administrator who gave you this login. Tell them your device, app version and the error shown.','請聯絡提供登入資料的管理員，告知裝置、app 版本及畫面上的錯誤。')}</p><p class="small">${t('Keep your password, private link and QR code to yourself.','請勿分享密碼、私人連結或 QR 碼。')}</p></section></div>`;}
function preserveView(update){
  const active=document.activeElement,id=active?.id;
  const x=globalThis.scrollX,y=globalThis.scrollY;
  const bars=$('#portal-history')?.querySelectorAll?.('.usage-bar');
  const barIndex=bars?Array.from(bars).indexOf(active):-1;
  update();
  if(id&&document.getElementById(id)!==active)document.getElementById(id)?.focus({preventScroll:true});
  else if(barIndex>=0)$('#portal-history')?.querySelectorAll?.('.usage-bar')[barIndex]?.focus({preventScroll:true});
  if(typeof globalThis.scrollTo==='function'&&typeof x==='number'&&typeof y==='number')globalThis.scrollTo(x,y);
}
function patchRefresh(){
  const status=$('#portal-refresh-state');if(status)status.innerHTML=refreshMarkup();
  const button=$('#refresh');if(button)button.disabled=refreshState==='refreshing';
  if($('#retry-refresh'))$('#retry-refresh').onclick=()=>refreshCurrent();
}
function patchData(historyChanged=false){
  if(!current)return;
  preserveView(()=>{
    if($('#portal-heading'))$('#portal-heading').innerHTML=heading();
    if($('#portal-accounting-warning'))$('#portal-accounting-warning').innerHTML=accountingWarning();
    if(page==='overview'&&$('#portal-quota'))$('#portal-quota').innerHTML=quotaSummary();
    if($('#portal-plan-summary'))$('#portal-plan-summary').innerHTML=page==='overview'?overviewExtras():plan();
    if(historyChanged&&$('#portal-history')){
      $('#portal-history').innerHTML=historyBody();
      if(page==='usage'&&usage&&!$('#history-picker'))$('#portal-history-controls').innerHTML=SBOXUsage.picker('history-picker',usage,lang);
    }
    $('#content').setAttribute('aria-busy',usageLoading?'true':'false');patchRefresh();bind();
  });
}
function quotaSummary(){const d=current;return `<div class="grid metrics"><section class="card"><p class="metric-label">${t('Used this cycle','今期已用')}</p><div class="big">${qsize(d.used_bytes)}</div><p class="metric-note">↑ ${qsize(d.upload_bytes)} · ↓ ${qsize(d.download_bytes)}</p>${!d.unlimited&&d.quota_bytes>0?`<progress aria-label="${t('Share of your data allowance used','已用數據比例')}" max="100" value="${Math.min(100,(d.used_bytes||0)/d.quota_bytes*100)}"></progress><p class="metric-note">${Math.min(100,Math.round((d.used_bytes||0)/d.quota_bytes*100))}% ${t('of','／')} ${qsize(d.quota_bytes)}</p>`:''}</section><section class="card"><p class="metric-label">${t('Remaining','尚餘')}</p><div class="big">${d.unlimited?t('No limit','無上限'):qsize(d.remaining_bytes)}</div><p class="metric-note">${t('Allowance this cycle','今期數據用量')}: ${d.unlimited?t('No limit','無上限'):qsize(d.quota_bytes)}</p></section><section class="card"><p class="metric-label">${t('Next reset','下次重設')}</p><div class="big">${d.next_reset?esc(new Date(d.next_reset*1000).toLocaleDateString(lang==='zh'?'zh-Hant-HK':'en-GB',{timeZone:d.timezone,month:'short',day:'numeric'})):t('No reset','不重設')}</div><p class="metric-note">${esc(d.timezone)} · ${d.next_reset?esc(new Date(d.next_reset*1000).toLocaleTimeString(lang==='zh'?'zh-Hant-HK':'en-GB',{timeZone:d.timezone,hour:'2-digit',minute:'2-digit'})):t('Lifetime plan','累積方案')}</p></section></div>`;}
function plan(){const d=current, periods={none:t('Never','不重設'),daily:t('Every day','每日'),weekly:t('Every week','每週'),monthly:t('Every month','每月')};return `<div class="grid"><section class="card"><h2>${t('Your plan','你的方案')}</h2><dl><dt>${t('Access','存取狀態')}</dt><dd>${esc(statusName(d.status))}</dd><dt>${t('Data allowance','數據用量')}</dt><dd>${d.unlimited?t('No limit','無上限'):qsize(d.quota_bytes)}</dd><dt>${t('Reset schedule','重設週期')}</dt><dd>${esc(periods[d.period]||d.period)}</dd><dt>${t('Cycle began','本期開始')}</dt><dd>${esc(date(d.period_start))}</dd><dt>${t('Next reset','下次重設')}</dt><dd>${d.next_reset?esc(date(d.next_reset)):t('No scheduled reset','沒有定期重設')}</dd><dt>${t('Timezone','時區')}</dt><dd>${esc(d.timezone)}</dd><dt>${t('Service ends','服務到期')}</dt><dd>${d.expires_at?esc(date(d.expires_at)):t('No end date','不設到期')}</dd></dl></section><section class="card"><h2>${t('How usage is counted','用量點樣計算')}</h2><p class="muted">${t('Your VPN data usage includes uploads and downloads. Your device or internet provider may show a different total.','VPN 用量包括上傳及下載。裝置或網路供應商顯示的總數可能不同。')}</p><p class="muted">${t('Historical charts follow the selected dates. Cycle usage follows your reset schedule, so their totals may differ. Ask your administrator to change your plan or expiry.','歷史圖表按所選日期計算；本期用量按重設週期計算，兩者總量可能不同。如需調整方案或到期時間，請聯絡管理員。')}</p><p class="small">${t('Usage updated','用量更新於')} ${esc(date(d.sampled_at))}</p><details><summary>${t('Technical details','技術詳情')}</summary><p>${t('Usage counts the data you send and receive through the VPN (upload plus download). Encryption overhead and other traffic on the server are not included. Times with no measurement are shown as missing, never as zero.','用量計算你經 VPN 傳送及接收的數據（上傳加下載），不包括加密開銷及伺服器其他流量。未量度到的時段會顯示為缺漏，不會當作零。')}</p></details></section></div>`;}
function account(){return `<section class="card"><h2>${t('Change password','更改密碼')}</h2><p class="muted">${current.reset_password?t('Change the initial password before accessing your personal information or connection.','請先更改初始密碼，然後查看個人資料同連線設定。'):t('Choose a password that is different from your VPN credentials. Changing it signs out your personal sessions.','請選用與 VPN 憑證不同的密碼。更改後會登出個人工作階段。')}</p><form id="change" class="password-form"><input class="sr" type="text" autocomplete="username" value="${esc(current.username||current.display_name||'')}" readonly tabindex="-1" aria-hidden="true"><label for="old">${t('Current password','目前密碼')}<input id="old" type="password" autocomplete="current-password" required maxlength="256"></label><div class="password-pair"><label for="new">${t('New password','新密碼')}<input id="new" type="password" minlength="14" maxlength="256" autocomplete="new-password" required aria-describedby="new-help"><span class="field-help" id="new-help">${t('At least 14 characters. Use something different from your VPN details.','最少 14 個字元，請使用與 VPN 資料不同的密碼。')}</span></label><label for="repeat">${t('Confirm new password','再輸入新密碼')}<input id="repeat" type="password" minlength="14" maxlength="256" autocomplete="new-password" required aria-describedby="repeat-help"><span class="field-help" id="repeat-help">${t('Type the same new password again.','請再輸入同一個新密碼。')}</span></label></div><div class="form-actions"><button type="submit" class="primary">${t('Save and sign in again','儲存並重新登入')}</button></div></form></section>`;}
function connectionPage(){return `<section class="card"><h2>${t('Connect & export','連線與匯出')}</h2>${connection?connectionBody():`<p class="muted">${t('Show your private connection to choose an app, routing profile and connection method.','顯示你的私人連線，以選擇 app、路由設定檔及連線方式。')}</p><button type="button" class="primary" id="reveal">${t('Show my connection','顯示我的連線')}</button>`}</section>`;}
// The ONE export implementation (frontend-src/shared/export-center.js), fed by this
// session's own endpoints; the user identity is derived by the server, never sent.
function connectionBody(){const c=connection;return `${c.state==='legacy'?`<p class="notice">${t('Your existing link still works, but this server cannot show it. Use your saved copy, or replace it below.','現有連結仍有效，但伺服器無法顯示。請使用已存副本，或在下方更換。')}</p>`:c.state==='key_unavailable'?`<p class="notice">${t('Your link still works. Ask your administrator to restore the matching private backup before showing it.','連結仍有效。請管理員先還原相符的私人備份，再顯示連結。')}</p>`:''}<div id="portal-export"></div><div class="actions"><button id="hide-link" type="button">${t('Hide private details','隱藏私人資料')}</button></div><details class="advanced-connect"${c.active?'':' open'}><summary>${t('Manage subscription link','管理訂閱連結')}</summary><p class="small">${c.active?t('Replace: creates a new subscription URL; the current URL and its QR code stop working at once and every device must import the new one. Revoke: stops your subscription URL until a new one is created. Neither changes your VPN credentials, so imported static files and single-server links keep working.','更換：建立新的訂閱網址，目前網址及其 QR 碼立即失效，每部裝置都要匯入新網址。撤銷：停用訂閱網址，直至建立新連結。兩者都不會更改 VPN 憑證，已匯入的靜態檔案及單一伺服器連結仍可使用。'):t('You have no active subscription link. Creating one does not change your VPN credentials.','你沒有有效的訂閱連結。建立連結不會更改 VPN 憑證。')}</p><div class="actions"><button id="replace" type="button"${c.active?'':' class="primary"'}>${c.active?t('Replace link…','更換連結…'):t('Create subscription link','建立訂閱連結')}</button>${c.active?`<button id="revoke" type="button" class="danger">${t('Revoke link…','撤銷連結…')}</button>`:''}</div></details>`;}
// bind() runs after every data patch; remount only for a new host or a new connection so a
// background refresh never resets the user's choices or an open QR code.
function mountPortalExport(){const host=$('#portal-export');if(!host||!connection?.catalog||typeof SBOXExportCenter==='undefined')return;if(host.__sboxConnection===connection)return;host.__sboxConnection=connection;SBOXExportCenter.mount(host,{catalog:connection.catalog,lang:()=>lang,adapter:{
 qrSubscription:async sel=>(await api('me/qr',{profile:sel.profile,format:sel.format,endpoint:sel.endpoint})).svg,
 nodes:async sel=>protocolUris((await api('me/export',{profile:sel.profile,format:'links',endpoint:sel.endpoint})).content),
 qrNode:async(sel,index)=>(await api('me/node-qr',{profile:sel.profile,index,endpoint:sel.endpoint})).svg,
 download:async sel=>(await api('me/export',{profile:sel.profile,format:sel.format,endpoint:sel.endpoint})).content}});}
function protocolUris(content){return String(content).split(/\r?\n/).map(x=>x.trim()).filter(x=>/^(vless|vmess|hysteria2|tuic|anytls):\/\//.test(x));}

function friendlyUsage(html){
  const phrases=[['Use left and right arrows to inspect each bucket.','Use the arrow keys to explore each time period.'],['所選範圍的實測上傳及下載，可用左右方向鍵查看每個時段。','所選日期的上傳及下載，可用左右方向鍵查看各時段。'],['Partial coverage · measured lower bound','Some records are missing · actual usage may be higher'],['部分觀測 · 實測下限','有紀錄缺漏 · 實際用量可能較多'],['Before local history collection','Before usage recording began'],['本地歷史記錄啟用前','開始記錄用量之前'],['Partial intervals are measured lower bounds.','Where records are missing, actual usage may be higher.'],['部分時段只顯示實測下限。','有紀錄缺漏的時段，實際用量可能較多。'],['This range has incomplete history. Data before collection or during gaps is not filled with zero.','Some usage records are missing for these dates. Missing records are not counted as zero.'],['此範圍有不完整紀錄。啟用前或計量中斷期間的資料不會以零填補。','這段時間有部分用量紀錄缺漏；缺漏不代表用量為零。']];
  for(const [from,to] of phrases)html=html.split(from).join(to);return html;
}
function historyBody(){return usage?friendlyUsage(SBOXUsage.render(usage,lang,{limit:current?.quota_bytes||null})):`<p class="muted" role="status">${usageLoading?t('Loading your usage…','正在載入用量…'):t('No history loaded. Use Refresh to retry.','尚未載入歷史，請按「重新整理」重試。')}</p>`;}
function chartCard(full){return `<section class="card"><div class="card-heading"><h2>${full?t('Usage history','歷史用量'):t('Recent activity','最近活動')}</h2><button id="${full?'export-usage':'all-usage'}" type="button" ${full&&!usage?'disabled':''}>${full?t('Export CSV','匯出 CSV'):t('View usage','查看用量')}</button></div><div id="portal-history-controls">${full?(usage?SBOXUsage.picker('history-picker',usage,lang):''):`<p class="small">${t('Last 24 hours · by hour','最近 24 小時 · 按小時計算')}</p>`}</div><div id="portal-history">${historyBody()}</div></section>`;}
function render(){
  clearNodeQr();connectionView++;if(qrUrl){URL.revokeObjectURL(qrUrl);qrUrl=null}
  const focused=document.activeElement?.id;shell();if(!current)return login();if(current.reset_password)page='account';
  const nav=$('#portal-nav');nav.hidden=false;nav.innerHTML=Object.entries(labels()).map(([key,label])=>`<button type="button" id="nav-${key}" data-page="${key}" ${key===page?'aria-current="page"':''} ${current.reset_password&&key!=='account'?'disabled':''}>${esc(label)}</button>`).join('');
  const body=page==='overview'?`<div id="portal-quota">${quotaSummary()}</div>`+chartCard(false)+`<div id="portal-plan-summary">${overviewExtras()}</div>`:page==='usage'?chartCard(true):page==='connection'?connectionPage():page==='plan'?`<div id="portal-plan-summary">${plan()}</div>`:account();
  $('#content').innerHTML=`<div id="portal-heading">${heading()}</div><p id="portal-refresh-state" class="small" role="status" aria-live="polite">${refreshMarkup()}</p><div id="portal-accounting-warning">${accountingWarning()}</div>`+body;
  $('#content').setAttribute('aria-busy',usageLoading?'true':'false');bind();
  if(focused)document.getElementById(focused)?.focus({preventScroll:true});
}
async function act(event,fn){const version=generation,button=event.target.closest('form')?.querySelector('button[type=submit]')||event.target.closest('button');if(button)button.disabled=true;message();try{await fn()}catch(error){if(version===generation||(!current&&error.sessionEnded))message(error.message)}finally{if(button)button.disabled=false}}
// A session boundary invalidates every earlier request without changing the server's CSRF contract.
async function signIn(event){
  if(loginAttempt?.session===authGeneration)return;
  const task={version:generation,session:authGeneration};loginAttempt=task;
  try{await act(event,async()=>{
    const result=await api('login',{username:$('#username').value,password:$('#password').value});
    if(task!==loginAttempt||task.version!==generation||task.session!==authGeneration)return;
    authGeneration++;generation++;historySequence++;refreshSequence++;refreshTask=null;historyTask=null;
    checkedAt=null;refreshState='idle';refreshError='';historyParams={window:'30d'};
    csrf=result.csrf;page='overview';await load();
  })}finally{if(loginAttempt===task)loginAttempt=null}
}
async function changeHistory(event){
  const task={version:generation,request:++historySequence};historyTask=task;
  try{await act(event,async()=>{
    const params=SBOXUsage.params(event.target);
    const data=await api('me/history?'+new URLSearchParams(params));
    if(task.version!==generation||task.request!==historySequence)return;
    historyParams=params;usage={...data,selected_start:params.start,selected_end:params.end};
    usageLoading=false;patchData(true);
  })}finally{if(historyTask===task)historyTask=null}
}
async function openPage(next){
  if(!current)return;generation++;historySequence++;
  if(next!=='connection')clearConnection();page=next;usage=null;
  usageLoading=(page==='overview'||page==='usage')&&!current.reset_password;message();render();
  await refreshCurrent();
}
async function refreshCurrent({initial=false}={}){
  if(document.hidden||!csrf||(!current&&!initial))return;
  if(refreshTask?.version===generation)return refreshTask.promise;
  const version=generation,request=++refreshSequence,task={version};refreshTask=task;
  refreshState='refreshing';refreshError='';patchRefresh();
  task.promise=(async()=>{
    try{
      const result=await api('me');
      if(version!==generation||request!==refreshSequence)return;
      const wasEmpty=!current;current=result;checkedAt=Date.now()/1000;
      if(current.reset_password&&page!=='account'){page='account';usage=null;usageLoading=false;clearConnection();render()}
      else if(wasEmpty)render();else patchData();
      if((page==='overview'||page==='usage')&&!current.reset_password&&historyTask?.version!==version){
        usageLoading=true;const historyRequest=++historySequence,params=page==='overview'?{window:'24h'}:historyParams;
        const data=await api('me/history?'+new URLSearchParams(params));
        if(version!==generation||request!==refreshSequence||historyRequest!==historySequence)return;
        usage={...data,selected_start:params.start,selected_end:params.end};
      }
      if(version!==generation||request!==refreshSequence)return;
      usageLoading=false;refreshState='fresh';patchData(true);
    }catch(error){
      if(version!==generation||request!==refreshSequence)return;
      usageLoading=false;refreshState='stale';refreshError=error.message;
      if(current)patchData();else{login();message(error.message)}
    }finally{if(refreshTask===task){refreshTask=null;if(refreshState==='refreshing'){usageLoading=false;refreshState='fresh';patchRefresh()}}}
  })();
  return task.promise;
}
function confirmLink(operation){const dialog=$('#confirm-dialog');$('#confirm-title').textContent=operation==='replace'?t('Replace private link?','更換私人連結？'):t('Revoke private link?','撤銷私人連結？');$('#confirm-description').textContent=operation==='replace'?t('Your current subscription URL and its QR code stop working immediately. Import the new URL on every device. VPN credentials stay the same.','目前的訂閱網址及其 QR 碼會立即失效。請在每部裝置匯入新網址。VPN 憑證保持不變。'):t('Your subscription URL and QR code stop working immediately and your apps can no longer update the profile. VPN credentials stay the same.','訂閱網址及 QR 碼會立即失效，app 將無法再更新設定檔。VPN 憑證保持不變。');$('#confirm-cancel').textContent=t('Cancel','取消');$('#confirm-submit').textContent=operation==='replace'?t('Replace link','更換連結'):t('Revoke link','撤銷連結');$('#confirm-cancel').onclick=()=>dialog.close();$('#confirm-submit').onclick=e=>act(e,async()=>{const version=generation,result=await api('me/'+(operation==='replace'?'replace-link':'revoke-link'),{confirm:true});dialog.close();if(version!==generation)return;connection=result;render()});dialog.showModal();$('#confirm-cancel').focus();}
function bind(){mountPortalExport();document.querySelectorAll('[data-page]').forEach(button=>button.onclick=()=>openPage(button.dataset.page));$('#logout').onclick=e=>act(e,async()=>{await api('logout',{});endSession()});if($('#refresh'))$('#refresh').onclick=()=>refreshCurrent();if($('#retry-refresh'))$('#retry-refresh').onclick=()=>refreshCurrent();const links={'go-connect':'connection','go-plan':'plan','all-usage':'usage'};Object.entries(links).forEach(([id,target])=>{if($('#'+id))$('#'+id).onclick=()=>openPage(target)});if($('#reveal'))$('#reveal').onclick=e=>act(e,async()=>{const version=generation;const result=await api('me/connection',{});if(version!==generation)return;connection=result;render()});if($('#hide-link'))$('#hide-link').onclick=()=>{clearConnection();render()};if($('#replace'))$('#replace').onclick=e=>{if(connection.active)confirmLink('replace');else act(e,async()=>{const version=generation,result=await api('me/replace-link',{confirm:true});if(version!==generation)return;connection=result;render()})};if($('#revoke'))$('#revoke').onclick=()=>confirmLink('revoke');if($('#change'))$('#change').onsubmit=e=>{e.preventDefault();act(e,async()=>{if($('#new').value!==$('#repeat').value)throw new Error(t('Passwords do not match.','兩次輸入的密碼不相同。'));await api('me/change-password',{old:$('#old').value,password:$('#new').value});endSession();message(t('Password changed. Sign in again.','密碼已更改，請重新登入。'))})};if($('#history-picker'))$('#history-picker').onsubmit=e=>{e.preventDefault();return changeHistory(e)};if($('#export-usage')){$('#export-usage').disabled=!usage;$('#export-usage').onclick=()=>{if(usage)SBOXUsage.download(usage)}};}
async function load(){const version=generation;try{if(!csrf){const session=await api('session');if(version!==generation)return;if(session.requires_signin){endSession(t('Sign in again to use connection and account actions.','請重新登入，以使用連線同帳戶功能。'));return}csrf=session.csrf}await refreshCurrent({initial:true})}catch(error){if(version===generation)message(error.message)}}
$('#language').onclick=()=>{lang=lang==='zh'?'en':'zh';save('sbox-portal-lang',lang);render()};$('#theme').onchange=()=>{theme=$('#theme').value;save('sbox-portal-theme',theme);shell()};matchMedia('(prefers-color-scheme:light)').addEventListener('change',()=>{if(theme==='system')shell()});shell();load();

// Poll only while visible; every response still observes the current session/page generation.
if(typeof setInterval==='function')setInterval(()=>refreshCurrent(),30000);
document.addEventListener?.('visibilitychange',()=>{if(!document.hidden)return refreshCurrent()});
