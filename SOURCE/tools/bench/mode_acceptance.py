#!/usr/bin/env python3
"""Isolated loopback transport acceptance. Synthetic identities and CA; never a WAN claim.
Run without root. Evidence is sanitized; private configs/logs remain under --work.
"""
import argparse,hashlib,http.server,importlib.util,json,os,shutil,socket,subprocess,sys,threading,time
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tests'));import reality_fixture as fx
spec=importlib.util.spec_from_file_location('transport',Path(__file__).with_name('dual_stack_acceptance.py'));b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
PAYLOAD=hashlib.sha256(b'sbox-mode-integrity').digest()*32768
class HTTP(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  value=b'ok' if self.path=='/health' else PAYLOAD;self.send_response(200);self.send_header('Content-Length',str(len(value)));self.end_headers();self.wfile.write(value)
 def do_POST(self):
  value=self.rfile.read(int(self.headers['Content-Length']));data=json.dumps({'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest()}).encode();self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
class HTTP6(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--core',type=Path,required=True);ap.add_argument('--mihomo',type=Path,help='Required only when selecting the Mihomo engine');ap.add_argument('--work',type=Path,required=True);ap.add_argument('--modes',default='ipv4,dual,ipv6');ap.add_argument('--engines',default='mihomo,sing-box');ap.add_argument('--protocols',default='reality,vmess,hy2,tuic,anytls');ap.add_argument('--samples',type=int,default=2);ap.add_argument('--skip-negative',action='store_true');args=ap.parse_args()
 if not 1<=args.samples<=20:ap.error('--samples must be 1..20')
 if 'mihomo' in args.engines.split(',') and (args.mihomo is None or not args.mihomo.is_file()):ap.error('--mihomo must point to the selected Mihomo CLI')
 W=args.work.resolve();(W/'private').mkdir(parents=True,exist_ok=True,mode=0o700);(W/'evidence').mkdir(exist_ok=True);b.W=W;b.CORE=str(args.core.resolve());(W/'mihomo').symlink_to(args.mihomo.resolve()) if args.mihomo and not (W/'mihomo').exists() else None
 certs=W/'private/certificates';ca,leaves=fx.lab_certificates(certs);(certs/'live').mkdir();shutil.copy2(leaves[fx.DOMAIN][0],certs/'live/fullchain.pem');shutil.copy2(leaves[fx.DOMAIN][1],certs/'live/privkey.pem');os.environ['SSL_CERT_FILE']=str(ca);os.environ['SSL_CERT_DIR']=str(certs)
 (W/'private/upload.bin').write_bytes(PAYLOAD)
 h4=http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTP);h6=HTTP6(('::1',0),HTTP)
 for h in [h4,h6]:threading.Thread(target=h.serve_forever,daemon=True).start()
 fp=b.free_port();fallback_log=(W/'private/fallback.log').open('wb');fallback=subprocess.Popen(['openssl','s_server','-quiet','-accept','127.0.0.1:'+str(fp),'-cert',str(leaves[fx.DOMAIN][0]),'-key',str(leaves[fx.DOMAIN][1]),'-www'],stdout=fallback_log,stderr=fallback_log)
 private,public=fx.reality_keypair();rows=[];resources=[]
 def emit(ok,**value):
  rows.append({'status':'NEW_PASS' if ok else 'FAIL',**value});(W/'evidence/results.json').write_text(json.dumps(rows,indent=2))
 try:
  for mode in args.modes.split(','):
   state=fx.self_hosted(fx.base_state(private,public),port=fp);state['server'].update(scope='internal',mode=mode,ipv4='127.0.0.1',ipv6='::1',listen={'ipv4':'0.0.0.0','dual':'::','ipv6':'::1'}[mode]);state['server_dns']={'optimistic':True}
   for name,p in state['protocols'].items():p.update(enabled=True,port=b.free_port())
   state['certificate'].update(source_fullchain=str(leaves[fx.DOMAIN][0]),source_key=str(leaves[fx.DOMAIN][1]))
   out=fx.render(state,cert_dir=str(certs));config=out/'server.json';serverlog=(W/'private'/('server-'+mode+'.log')).open('wb');server=subprocess.Popen([b.CORE,'run','-c',str(config)],stdout=serverlog,stderr=serverlog)
   try:
    for _ in range(100):
     if server.poll() is not None:raise RuntimeError('core failed; inspect private server log')
     try:
      with socket.create_connection(('::1' if mode=='ipv6' else '127.0.0.1',state['protocols']['reality']['port']),timeout=.1):break
     except OSError:time.sleep(.03)
    profile=yaml.safe_load((out/'mihomo-global.yaml').read_text())
    families=['ipv4','ipv6'] if mode=='dual' else [mode]
    for family in families:
     addr='::1' if family=='ipv6' else '127.0.0.1';target='http://[::1]:'+str(h6.server_port) if family=='ipv6' else 'http://127.0.0.1:'+str(h4.server_port)
     for engine in args.engines.split(','):
      for p in profile['proxies']:
       protocol=b.names[p['type']]
       if protocol not in args.protocols.split(','):continue
       ctx={'mode':mode,'family':family,'engine':engine,'protocol':protocol};work=W/'private'/mode/family/engine/protocol;port=b.free_port();proc=log=None
       try:
        proc,log=b.start(engine,p,addr,port,work)
        for sample in range(args.samples):
         rc,data,timing=b.curl(port,target,'/health');emit(rc==0 and data==b'ok',test='cold-health' if sample==0 else 'warm-health',**ctx,**timing)
        rc,data,timing=b.curl(port,target,'/payload');emit(rc==0 and data==PAYLOAD,test='1MiB-download-integrity',sha256=hashlib.sha256(data).hexdigest(),**ctx,**timing)
        rc,data,timing=b.curl(port,target,upload=True)
        try:ok=json.loads(data)=={'bytes':len(PAYLOAD),'sha256':hashlib.sha256(PAYLOAD).hexdigest()}
        except ValueError:ok=False
        emit(rc==0 and ok,test='1MiB-upload-integrity',**ctx,**timing)
        if mode!='dual':
         other='http://[::1]:'+str(h6.server_port) if mode=='ipv4' else 'http://127.0.0.1:'+str(h4.server_port);rc,data,timing=b.curl(port,other,'/health',timeout=2);emit(rc!=0 and data!=b'ok',test='opposite-family-rejected',**ctx)
       except Exception as e:emit(False,test='client-error',error=str(e),**ctx)
       finally:
        if proc:b.stop(proc,log)
       if not args.skip_negative:
        proc=log=None
        try:
         port=b.free_port();proc,log=b.start(engine,p,addr,port,work/'wrong',True);rc,data,timing=b.curl(port,target,'/health',timeout=2);emit(rc!=0 and data!=b'ok',test='wrong-credentials',**ctx)
        except Exception as e:emit(False,test='wrong-credentials',error=str(e),**ctx)
        finally:
         if proc:b.stop(proc,log)
       raw=Path('/proc/'+str(server.pid)+'/status').read_text();rss=next(int(l.split()[1])*1024 for l in raw.splitlines() if l.startswith('VmRSS:'));ticks=Path('/proc/'+str(server.pid)+'/stat').read_text().split()
       resources.append({**ctx,'core_rss_bytes':rss,'core_cpu_ticks':int(ticks[13])+int(ticks[14]),'config_sha256':hashlib.sha256(config.read_bytes()).hexdigest()})
       (W/'evidence/resources.json').write_text(json.dumps(resources,indent=2))
   finally:b.stop(server,serverlog)
 finally:
  b.stop(fallback,fallback_log)
  for h in [h4,h6]:h.shutdown();h.server_close()
 summary={'scope':'synthetic loopback integration; neither public IPv6 nor physical client evidence','core_sha256':hashlib.file_digest(args.core.open('rb'),'sha256').hexdigest(),'rows':len(rows),'passed':sum(r['status']=='NEW_PASS' for r in rows),'failed':[r for r in rows if r['status']=='FAIL']};(W/'evidence/summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2));return bool(summary['failed'])
if __name__=='__main__':sys.exit(main())
