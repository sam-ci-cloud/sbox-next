/* Run every automatic browser/JS regression in isolated processes. */
const fs=require('fs'),path=require('path'),{spawnSync}=require('child_process');
const root=path.resolve(__dirname,'../..'),tests=path.join(root,'shared_webui/tests'),out=path.join(root,'.build/browser-results');
fs.mkdirSync(out,{recursive:true});const results=[];
for(const name of fs.readdirSync(tests).filter(n=>/^test_.*\.cjs$/.test(n)).sort()){
 const start=Date.now();const r=spawnSync(process.execPath,[path.join(tests,name),...(name==='test_layout_matrix_browser.cjs'?[path.join(out,'layout-matrix')]:[])],{cwd:root,encoding:'utf8',timeout:1200000,maxBuffer:16*1024*1024});
 const text=(r.stdout||'')+(r.stderr||'');fs.writeFileSync(path.join(out,name+'.log'),text);
 const row={suite:name,status:r.status===0?'PASS':'FAIL',exit:r.status,signal:r.signal,seconds:(Date.now()-start)/1000};results.push(row);console.log(JSON.stringify(row));
 if(r.status!==0)console.log(text.slice(-8000));
 fs.writeFileSync(path.join(out,'results.json'),JSON.stringify(results,null,2));
}
const failed=results.filter(r=>r.status==='FAIL').length;const summary={complete:true,suites:results.length,failed,status:results.length&&failed===0?'PASS':'FAIL'};
fs.writeFileSync(path.join(out,'summary.json'),JSON.stringify(summary,null,2));console.log(JSON.stringify(summary));process.exitCode=summary.status==='PASS'?0:1;
