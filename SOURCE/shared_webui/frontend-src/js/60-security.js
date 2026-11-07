/* Certificates (with DNS/ACME readiness), firewall & SSH guard, sign-in & sessions. */
pages.certificates = async function () {
  const [c, r] = await Promise.all([api('certificates'), api('certificates/readiness')]);
  const days = c.expires_at ? Math.floor((c.expires_at - Date.now() / 1000) / 86400) : null;
  const kind = days === null ? 'unknown' : days < 3 ? 'error' : days < 14 ? 'warning' : 'ok';
  return `
    <p class="page-intro">${esc(bi('The VPN and this panel use the same managed certificate. The panel keeps its own protected copy and refreshes it every five minutes without restarting the VPN.', 'VPN 與本面板使用同一張受管憑證。面板保有自己的受保護副本，每五分鐘更新一次，不會重新啟動 VPN。'))}</p>
    <div class="grid cols-2">
      <section class="panel"><h2>${esc(c.domain)}</h2>
        <p>${status(kind, days === null ? bi('No expiry date', '沒有到期日') : days < 0 ? bi('Expired', '已過期') : bi(`${days} days left`, `剩 ${days} 天`))}</p>
        <dl class="kv"><dt>${esc(bi('Mode', '模式'))}</dt><dd>${esc(c.mode)}</dd><dt>${esc(bi('Issuer', '簽發者'))}</dt><dd>${esc(c.issuer || '—')}</dd>
          <dt>${esc(bi('Valid from', '生效'))}</dt><dd>${esc(when(c.starts_at))}</dd><dt>${esc(bi('Expires', '到期'))}</dt><dd>${esc(when(c.expires_at))}</dd></dl>
        ${source(c.source)}
        ${isAdmin() && r.acme ? `<div class="actions mt" data-admin>${btn('renew-test', bi('Test renewal (dry run)', '測試續期（演練）'))}${btn('certificate-renew', bi('Renew now…', '立即續期…'), 'danger')}</div>` : ''}
        <div id="cert-out" class="mt"></div></section>
      <section class="panel"><h2>${esc(bi('Readiness for renewal', '續期準備'))}</h2>
        <div class="table-wrap"><table><caption class="sr">${esc(bi('Certificate prerequisites', '憑證先決條件'))}</caption><tbody>
        ${r.checks.map(x => `<tr><th scope="row">${esc(x.item)}</th><td>${status(x.status === 'info' ? 'info' : x.status)}<br><span class="small">${esc((x.value || []).join(', '))}</span>${x.note ? `<br><span class="muted small">${esc(x.note)}</span>` : ''}<p class="source">${esc(x.source || '')}</p></td></tr>`).join('')}
        </tbody></table></div>
        <p class="muted small mt">${esc(r.note)}</p></section>
    </div>`;
};

pages.security = async function () {
  const [d,guard] = await Promise.all([api('security/firewall'),api('security/webui-guard').catch(error=>{if(error.stale||error.handled)throw error;return null;})]);
  const ports = portRows(d);
  return `
    <p class="page-intro">${esc(bi('The manager owns one firewall table for the VPN ports and an early SSH guard. It never changes the default chains, SSH configuration or other software\'s rules. Provider security groups are outside the server and must be opened in the provider console.', '管理器只擁有一個用於 VPN 連接埠的防火牆表及早期 SSH 防護，永不變更預設鏈、SSH 設定或其他軟體的規則。供應商安全群組在伺服器之外，須於供應商主控台開放。'))}</p>
    ${webuiGuardCard(guard)}
    <section class="panel mt"><h2>${esc(bi('Ports the VPN needs', 'VPN 需要的連接埠'))}</h2>
      ${ports ? `<div class="table-wrap"><table><thead><tr><th scope="col">${esc(bi('Purpose', '用途'))}</th><th scope="col">${esc(bi('Port', '連接埠'))}</th><th scope="col">${esc(bi('Protocol', '協定'))}</th></tr></thead><tbody>${ports.map(p => `<tr><td>${esc(p.purpose)}</td><td><code>${esc(p.port)}</code></td><td>${esc(p.network)}</td></tr>`).join('')}</tbody></table></div>` : pre(d)}
      <p class="muted small mt">${esc(bi('SSH stays reachable: the guard rate-limits and bans abusive addresses but keeps your SSH port open.', 'SSH 保持可連線：防護只限制並封鎖濫用位址，SSH 連接埠維持開放。'))}${d.ssh_port ? ' SSH: ' + esc(d.ssh_port) : ''}</p></section>
    <div class="grid cols-2 mt">
      <section class="panel"><h2>${esc(bi('Inspect', '檢查'))}</h2><div class="actions">${btn('firewall-status', bi('Local firewall rules', '本機防火牆規則'))}${btn('bans', bi('Banned addresses', '已封鎖位址'))}${btn('security-status', bi('Fail2Ban status', 'Fail2Ban 狀態'))}</div><div id="security-out" class="mt"></div></section>
      ${isAdmin() ? `<section class="panel" data-admin><h2>${esc(bi('Repair', '修復'))}</h2>
        <p class="muted small">${esc(bi('Repairs only re-apply the manager\'s own rules. They do not restart SSH and do not touch UFW or other tables.', '修復只會重新套用管理器自己的規則，不會重新啟動 SSH，也不觸及 UFW 或其他表。'))}</p>
        <div class="actions">${btn('firewall-apply', bi('Reconcile VPN firewall rules…', '修復 VPN 防火牆規則…'))}${btn('security-repair', bi('Repair SSH guard…', '修復 SSH 防護…'))}</div>
        <form id="unban-form" class="toolbar mt" novalidate>${field('ip', bi('Unban IP address', '解除封鎖 IP 位址'), '', 'text', 'required autocomplete="off" inputmode="decimal"')}<button type="submit">${esc(bi('Unban', '解除封鎖'))}</button></form></section>` : ''}
    </div>`;
};

pages.access = async function () {
  const s = await api('auth/sessions');
  const me = state.me;
  return `
    <p class="page-intro">${esc(bi('Sessions end after 30 minutes without activity and after 8 hours at most. Sensitive actions ask for your password again (and your authenticator code when two-factor is on).', '工作階段閒置 30 分鐘或最長 8 小時後結束。敏感操作會再次要求密碼（啟用雙因素時另需驗證碼）。'))}</p>
    <div class="grid cols-2">
      <section class="panel"><h2>${esc(bi('Password', '密碼'))}</h2>
        <form id="settings-password" class="password-form" novalidate><input class="sr" type="text" autocomplete="username" value="${esc(me.name||me.username||'')}" readonly tabindex="-1" aria-hidden="true">${field('old', bi('Current password', '目前密碼'), '', 'password', 'autocomplete="current-password" required')}<div class="password-pair">${field('password', bi('New password', '新密碼'), '', 'password', 'autocomplete="new-password" minlength="12" required', bi('At least 12 characters.', '最少 12 個字元。'))}<label class="field"><span>${esc(bi('Confirm new password', '再輸入新密碼'))}</span><input id="settings-password-confirm" type="password" autocomplete="new-password" minlength="12" required></label></div>
        <p class="muted small">${esc(bi('Changing the password signs out your other sessions and revokes your API tokens.', '更改密碼會登出你的其他工作階段並撤銷你的 API 權杖。'))}</p><button type="submit" class="primary">${esc(bi('Change password', '更改密碼'))}</button></form></section>
      <section class="panel"><h2>${esc(bi('Two-factor authentication', '雙因素驗證'))}</h2>
        <p>${me.totp ? status('ok', bi('On', '已開啟')) : status('warning', bi('Off', '未開啟'))}</p>
        <p class="muted small">${esc(bi('Use any TOTP authenticator app. You get eight single-use recovery codes when you turn it on.', '可使用任何 TOTP 驗證器。開啟時會取得八組一次性復原碼。'))}</p>
        <div class="actions">${btn('totp-enroll', me.totp ? bi('Replace authenticator', '更換驗證器') : bi('Turn on', '開啟'), me.totp ? '' : 'primary')}${me.totp ? btn('totp-disable', bi('Turn off…', '關閉…'), 'danger') : ''}</div>
        <div id="totp-out" class="mt"></div></section>
    </div>
    <div class="section-title"><h2>${esc(bi('Active sessions', '使用中的工作階段'))}</h2>${s.sessions.filter(x => !x.current).length ? btn('sessions-revoke-others', bi('Sign out all other sessions', '登出所有其他工作階段'), 'danger') : ''}</div>
    <div class="table-wrap"><table><caption class="sr">${esc(bi('Your active sessions', '你的使用中工作階段'))}</caption>
      <thead><tr><th scope="col">${esc(bi('Device', '裝置'))}</th><th scope="col">${esc(bi('Address', '位址'))}</th><th scope="col">${esc(bi('Signed in', '登入時間'))}</th><th scope="col">${esc(bi('Last active', '最後活動'))}</th><th scope="col" class="actions-cell">${esc(bi('Action', '操作'))}</th></tr></thead>
      <tbody>${s.sessions.map(x => `<tr><td>${esc(shortAgent(x.agent))}${x.current ? ' ' + status('ok', bi('This session', '目前工作階段')) : ''}</td><td><code>${esc(x.ip)}</code></td><td>${esc(when(x.created))}</td><td>${esc(ago(x.last_seen))}</td>
        <td class="actions-cell">${x.current ? '—' : btn('session-revoke', bi('Sign out', '登出'), '', `data-id="${esc(x.id)}"`)}</td></tr>`).join('')}</tbody></table></div>`;
};

function shortAgent(agent) {
  if (!agent || agent === 'unknown') return bi('Unknown device', '未知裝置');
  const browser = /Edg\//.test(agent) ? 'Edge' : /Firefox\//.test(agent) ? 'Firefox' : /Chrome\//.test(agent) ? 'Chrome' : /Safari\//.test(agent) ? 'Safari' : 'Browser';
  const os = /iPhone|iPad/.test(agent) ? 'iOS' : /Android/.test(agent) ? 'Android' : /Windows/.test(agent) ? 'Windows' : /Mac OS X/.test(agent) ? 'macOS' : /Linux/.test(agent) ? 'Linux' : '';
  return browser + (os ? ' · ' + os : '');
}

/* Normalise both manager shapes: Generic {protocol_ports, hysteria2_hop_range}
   and ZgoCloud {protocol_ports, udp_hop_ranges}. */
function portRows(d) {
  if (!d || !Array.isArray(d.protocol_ports)) return null;
  const rows = d.protocol_ports.map(p => ({purpose: PROTOCOL_NAMES[p.name] || p.name, port: p.port, network: p.protocol}));
  if (d.hysteria2_hop_range) rows.push({purpose: 'Hysteria2 ' + bi('port hopping', '跳埠'), port: d.hysteria2_hop_range.range, network: 'udp'});
  (d.udp_hop_ranges || []).forEach(h => rows.push({purpose: (PROTOCOL_NAMES[h.name] || h.name) + ' ' + bi('port hopping', '跳埠') + ' → ' + h.main_port, port: h.range, network: 'udp'}));
  return rows;
}
