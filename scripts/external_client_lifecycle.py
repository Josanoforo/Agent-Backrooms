"""Reconcile a terminated client without replaying its task or changing its trace."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def reconcile(folder, root):
    folder,root=Path(folder),Path(root)
    trace=folder/'trace.json'
    if not trace.is_file():return {'status':'no_trace','cleanup_confirmed':None}
    original=trace.read_bytes();doc=json.loads(original)
    if doc.get('cleanup_confirmed') is True:return {'status':'closed','cleanup_confirmed':True}
    receipt=folder/'recovery-client-exit.json'
    if receipt.exists() and json.loads(receipt.read_text(encoding='utf-8')).get('status') not in ('recovered','already_closed'):
        attempt=2
        while (folder/('recovery-client-exit-'+str(attempt)+'.json')).exists():attempt+=1
        receipt=folder/('recovery-client-exit-'+str(attempt)+'.json')
    if not receipt.exists():
        call=subprocess.run([sys.executable,'-X','utf8',str(root/'scripts/recover_external_session.py'),
            '--db',str(folder/'bridge-state.sqlite3'),'--report',str(receipt),'--operator-control-dir',str(folder)],
            capture_output=True,text=True,encoding='utf-8')
        if call.returncode or not receipt.exists():
            return {'status':'recovery_failed','cleanup_confirmed':None,'client_exit_recovery_code':call.returncode}
    result=json.loads(receipt.read_text(encoding='utf-8'))
    if result.get('status') in ('recovered','already_closed'):
        def runtime_path(path):
            return subprocess.check_output(['wsl.exe','-e','wslpath','-a',str(Path(path).resolve())],text=True).strip() if os.name=='nt' else str(Path(path).resolve())
        program=('import json,sys;sys.path.insert(0,'+repr(runtime_path(root))+');'
            'from services.agent.external_bridge import TraceStore;'
            'd=TraceStore('+repr(runtime_path(folder/'bridge-state.sqlite3'))+').report('+repr(doc['run_id'])+');'
            'print(json.dumps(d))')
        command=['wsl.exe','-e','/usr/bin/python3','-c',program] if os.name=='nt' else [sys.executable,'-B','-c',program]
        data=subprocess.check_output(command)
        recovered=json.loads(data)
        assert recovered['run_id']==doc['run_id'] and recovered['cleanup_confirmed'] is True
        target=folder/'trace-recovered.json'
        if not target.exists():target.write_bytes(data)
        assert trace.read_bytes()==original
        return {'status':'recovered','cleanup_confirmed':True,'original_trace_sha256':hashlib.sha256(original).hexdigest(),
            'recovered_trace':target.name,'original_trace_preserved':True}
    return {'status':result['status'],'cleanup_confirmed':None,'receipt':receipt.name}


if __name__=='__main__':
    root=Path(__file__).resolve().parents[1]
    print(json.dumps(reconcile(root/'.private/external-agent'/sys.argv[1],root)))
