// WebUI custom-rule tester must parse IPv6 literals, bracketed URLs and IP-CIDR6 (UI-02).
// Old behaviour: host = target.split(':')[0], so "2001:db8::1" became "2001" and
// "https://[2001:db8::1]/" became "[2001"; IP-CIDR6 rules were never evaluated.
const assert = require('assert/strict'), fs = require('fs'), vm = require('vm'), path = require('path');
const state = {policy: {rules: [
  'IP-CIDR,192.168.0.0/16,REJECT',
  'IP-CIDR6,2001:db8::/32,DIRECT',
  'IP-CIDR6,fd00::/8,REJECT,no-resolve',
  'DOMAIN-SUFFIX,example.com,DIRECT',
  'IP-CIDR,10.0.0.0/8,🚀 VPN,no-resolve',
]}};
const context = {state, pages: {}, bi: en => en, esc: x => String(x), select: () => '', field: () => '', checkbox: () => ''};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../frontend-src/js/40-policy.js'), 'utf8'), context);
const t = target => vm.runInContext('testRule(' + JSON.stringify(target) + ')', context);
const hit = (target, rule) => assert.equal((t(target) || {}).rule, rule, target);

hit('192.168.1.2', 'IP-CIDR,192.168.0.0/16,REJECT');
hit('http://192.168.1.2:8080/x', 'IP-CIDR,192.168.0.0/16,REJECT');
hit('10.1.2.3', 'IP-CIDR,10.0.0.0/8,🚀 VPN,no-resolve');
assert.equal(t('10.1.2.3').action, '🚀 VPN', 'action is the third field even with no-resolve');
hit('2001:db8::1', 'IP-CIDR6,2001:db8::/32,DIRECT');
hit('2001:DB8:0:0::abcd', 'IP-CIDR6,2001:db8::/32,DIRECT');
hit('[2001:db8::1]', 'IP-CIDR6,2001:db8::/32,DIRECT');
hit('https://[2001:db8::1]:8443/path?q=1', 'IP-CIDR6,2001:db8::/32,DIRECT');
hit('fd12:3456::7', 'IP-CIDR6,fd00::/8,REJECT,no-resolve');
hit('2001:dbf::1', null);                         // outside 2001:db8::/32
hit('example.com:443', 'DOMAIN-SUFFIX,example.com,DIRECT');
hit('https://user@sub.example.com/a', 'DOMAIN-SUFFIX,example.com,DIRECT');
assert.equal(t('2001:db8::1').host, undefined, 'a hit returns the rule, not a truncated host');
assert.equal(t('2001:dbf::1').host, '2001:dbf::1', 'misses report the full IPv6 host');
hit('2001:::1', null);                            // invalid literal is not an IP match
assert.equal(t('   '), null);

// IPv4 rules never match IPv6 addresses and vice versa; /0 edge cases.
state.policy.rules = ['IP-CIDR6,::/0,REJECT', 'IP-CIDR,0.0.0.0/0,DIRECT'];
hit('2606:4700::1', 'IP-CIDR6,::/0,REJECT');
hit('8.8.8.8', 'IP-CIDR,0.0.0.0/0,DIRECT');
state.policy.rules = ['IP-CIDR6,2001:db8::1/128,DIRECT'];
hit('2001:db8::1', 'IP-CIDR6,2001:db8::1/128,DIRECT');
hit('2001:db8::2', null);

console.log('Rule tester: IPv4, IPv6 literals, bracketed URLs, IP-CIDR6 and edge cases passed.');
