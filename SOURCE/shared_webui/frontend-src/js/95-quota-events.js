Object.assign(actions,{
 'user-create':()=>userWizard(),'user-detail':el=>userDetail(el.dataset.id),
 'wizard-next':()=>wizardStep(Math.min(2,state.wizardStep+1)),'wizard-back':()=>wizardStep(Math.max(0,state.wizardStep-1)),
 'quota-pause':el=>prepareChange({kind:'quota',id:el.dataset.id,data:{action:'pause'}}),
 'quota-resume':el=>prepareChange({kind:'quota',id:el.dataset.id,data:{action:'resume'}}),
 'quota-reset':el=>prepareChange({kind:'quota',id:el.dataset.id,data:{action:'reset'}})
});
Object.assign(forms,{
 'quota-form':async form=>{required(form);return prepareChange({kind:'quota',id:form.dataset.id,data:await quotaData(values(form))})},
 'topup-form':form=>{required(form);return prepareChange({kind:'quota',id:form.dataset.id,data:{action:'topup',topup_bytes:values(form).amount+' '+values(form).unit}})},
 'portal-form':form=>{required(form);const d=values(form),data={username:d.username,enabled:form.elements.enabled.checked};if(d.password)data.password=d.password;return prepareChange({kind:'portal-account',id:form.dataset.id,data})},
 'new-user-wizard':async form=>{const d=values(form),data={name:d.name.trim(),subscription:true,protocols:$$('[data-new-protocol]:checked',form).map(x=>x.value),tags:d.tags.split(',').map(x=>x.trim()).filter(Boolean)};if(!data.protocols.length)throw new ApiError(422,bi('Select at least one protocol','請選擇至少一個協定'));if(state.accounting?.enabled)data.quota=await quotaData(d);if(form.elements.portal_enabled.checked){if(!d.portal_username||!d.portal_password)throw new ApiError(422,bi('Enter a portal username and initial password','請輸入入口網站名稱及初始密碼'));data.portal={username:d.portal_username,password:d.portal_password,enabled:true}}return prepareChange({kind:'user-create',data})}
});
actions['monitor-window']=el=>{state.monitorWindow=el.dataset.window;return render({keep:true})};
forms['host-budget-form']=async form=>{required(form);const d=values(form);await api('monitor/settings',{host_budget:{quota_bytes:d.quota_bytes,timezone:d.timezone,reset_day:Number(d.reset_day)}});return render({keep:true})};
forms['probe-settings']=async form=>{const lines=values(form).targets.split(/\r?\n/).map(x=>x.trim()).filter(Boolean),targets=lines.map(x=>{const [kind,host,port,...extra]=x.split(/\s+/);if(extra.length)throw new ApiError(422,bi('Use kind host port','請使用：種類 主機 連接埠'));return {kind,host,port:Number(port||443),enabled:true}});await api('monitor/settings',{targets});toast(bi('Probe settings saved','探測設定已儲存'));return render({keep:true})};

actions['bulk-quota']=async()=>{await ensureTimezones();return modal(bi('Set a data allowance for the selected users','為所選使用者設定數據用量'),`<form id="bulk-quota-form">${quotaFields()}<p class="muted">${esc(bi('All selected users are checked and changed together. Their current usage and any pauses are kept.','所選使用者會一併檢查同更改，保留現有用量同暫停狀態。'))}</p><button type="submit" class="primary">${esc(bi('Review assignment','檢視指派'))}</button></form>`);};
forms['bulk-quota-form']=async form=>{required(form);return prepareChange({kind:'quota-bulk',data:{ids:[...state.userView.selected],plan:await quotaData(values(form))}})};

Object.assign(actions, {
 'detail-tab':async el=>{const detail=state.detail;detail.tab=el.dataset.tab;renderUserDetail();$('#detail-tab-'+detail.tab)?.focus();const version=modalGeneration;if(detail.tab==='activity'&&!detail.activity){const result=await api('audit?text='+encodeURIComponent(detail.id)+'&limit=25');if(state.detail!==detail||version!==modalGeneration)return;detail.activity=result;if(detail.tab==='activity')renderUserDetail();}},
 'detail-export-usage':()=>SBOXUsage.download(state.detail.history),
 'detail-reveal':async()=>{const detail=state.detail,version=modalGeneration,r=await api('subscriptions/reveal',{id:detail.id});if(state.detail!==detail||version!==modalGeneration||detail.tab!=='connection')return;showLinks(r,'#detail-links',detail.id);$('#detail-links').insertAdjacentHTML('beforeend',`<div class="actions mt">${btn('user-share',bi('Manage subscription link','管理訂閱連結'),'',`data-id="${esc(detail.id)}"`)}</div>`);},
 'portal-generate':el=>{const form=el.closest('form'),input=form.querySelector('[name=portal_password],[name=password]'),random=crypto.getRandomValues(new Uint8Array(24));const alphabet='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.';input.value=Array.from(random,x=>alphabet[x%alphabet.length]).join('');input.type='text';input.select();toast(bi('Password generated','已產生密碼'),bi('Save it securely and share it privately. It takes effect after confirmation.','請安全儲存並私下交予使用者，確認變更後先會生效。'));}
});
forms['detail-history-picker']=async form=>{const detail=state.detail,version=modalGeneration,p=SBOXUsage.params(form),d=await api('accounting/history?id='+encodeURIComponent(detail.id)+'&'+new URLSearchParams(p));if(state.detail!==detail||version!==modalGeneration)return;detail.history={...d,selected_start:p.start,selected_end:p.end};renderUserDetail();};
document.addEventListener('keydown',event=>{const tab=event.target.closest('.detail-tabs [role=tab]');if(!tab||!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;event.preventDefault();const tabs=$$('.detail-tabs [role=tab]'),i=tabs.indexOf(tab),n=event.key==='Home'?0:event.key==='End'?tabs.length-1:(i+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;tabs[n].click();});
actions['timezone-retry']=async el=>{const root=el.closest('.plan-fields'),data=await ensureTimezones(true);if(data.source==='server'){root.querySelector('.timezone-source')?.remove();toast(bi('Time zone list loaded','已載入時區清單'),bi(`${data.timezones.length} time zones from this server.`,`伺服器提供 ${data.timezones.length} 個時區。`));}else toast(bi('Still using the browser list','仍然使用瀏覽器清單'),bi('The server list could not be loaded. Try again later.','未能載入伺服器清單，請稍後再試。'),'warning');};

actions['host-window']=el=>{state[el.dataset.key+'Window']=el.dataset.window;return render({keep:true});};
forms['host-range-form']=async form=>{
  required(form);const data=values(form),start=Date.parse(data.start)/1000,end=Date.parse(data.end)/1000,now=Date.now()/1000;
  if(!['traffic','monitor'].includes(data.key)||![start,end].every(Number.isFinite)||start>=end||start<now-30*86400||end>now+5)throw Error(bi('Choose an ordered range within the last 30 days.','請選擇最近 30 天內、開始早於結束的範圍。'));
  state[data.key+'Range']={start,end};state[data.key+'Window']='custom';return render({keep:true});
};
