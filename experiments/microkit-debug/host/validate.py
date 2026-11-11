"""Offline regression suite or explicit, six-attempt-capped live campaign."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from .backend import Backend, BackendError, MODEL, write_json
from .protocol import Request, Proposal
from .harness import ROOT, BROKER, ex, run_case, configurations, wanted


def commands_for_versions():
    result={}
    for tool,args in [('python',[sys.executable,'--version']),('clang',['clang','--version']),
                      ('qemu',['qemu-system-aarch64','--version']),('linker',['ld.lld','--version']),
                      ('git',['git','rev-parse','HEAD'])]:
        p=subprocess.run(args,cwd=ROOT,capture_output=True,text=True)
        result[tool]=(p.stdout or p.stderr).splitlines()[0] if (p.stdout or p.stderr) else ''
    result['sdk']=str(Path(os.environ['MICROKIT_SDK']).resolve())
    result['sdk_version']=(Path(os.environ['MICROKIT_SDK'])/'VERSION').read_text().strip()
    result['tracked_changes']=subprocess.check_output(['git','diff','--stat'],cwd=ROOT,text=True)
    return result


def offline(out):
    results=[]
    env=os.environ.copy();env.pop('MICROKIT_SDK',None);env['PYTHONDONTWRITEBYTECODE']='1'
    for label,cwd,command in [
        ('host-unit',ROOT,[sys.executable,'-m','unittest','discover','-s','host/tests','-v']),
        ('broker-host',BROKER,[sys.executable,'-m','unittest','discover','-s','tests','-v']),
        ('reference',ROOT/'email-fence',[sys.executable,'-m','unittest','-v'])]:
        p=subprocess.run(command,cwd=cwd,env=env,capture_output=True,text=True)
        (out/f'{label}.log').write_text(p.stdout+p.stderr)
        results.append(dict(check=label,command=command,exit=p.returncode,ok=p.returncode==0))
        if p.returncode:raise BackendError(label+' failed')
    # Host-specific built-capability negative tests need the SDK.
    p=subprocess.run([sys.executable,"-m","unittest","discover","-s","host/tests","-v"],cwd=ROOT,capture_output=True,text=True)
    (out/"host-integration.log").write_text(p.stdout+p.stderr)
    results.append(dict(check="host-integration",exit=p.returncode,ok=p.returncode==0))
    if p.returncode:raise BackendError("host capability integration tests failed")
    # All original system checks, including both 16-run matrices, release output and bypass probes.
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1'
    p=subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-v'],cwd=BROKER,env=env,capture_output=True,text=True)
    (out/'broker-full.log').write_text(p.stdout+p.stderr)
    results.append(dict(check='broker-full',exit=p.returncode,ok=p.returncode==0))
    if p.returncode:raise BackendError('original broker integration tests failed')
    for name in ex.configurations():
        r=run_case(name,Backend('scripted'),out/'matrix'/name)
        results.append(r)
        if not r['ok']:raise BackendError('host matrix failed: '+name)
    for policy in ['open','fenced']:
        name=f'{policy}-injected-s1-malicious-allowed'
        r=run_case(name,Backend('adversarial'),out/'adversarial'/policy)
        results.append(r)
        if not r['ok']:raise BackendError('adversarial control failed')
    for policy in ['open','fenced']:
        for fault in ['malformed','oversized','stale','duplicate','disconnect','timeout']:
            r=run_case(f'{policy}-injected-s1-malicious-allowed',Backend('adversarial'),out/'faults'/policy/fault,
                       fault=fault,timeout=3 if fault in ('disconnect','timeout') else 10)
            calls=[s for s in r['steps'] if s['caller']=='worker' and s['event']=='ACall']
            # A duplicate test starts with one valid reply: it may dispatch once,
            # before the duplicate arrives. The duplicate must never dispatch again.
            allowed=1 if fault=='duplicate' else 0
            r['expected_failure']=True
            r['fault_check_passed']=(not r['ok'] and len(calls)<=allowed
                and len(r['observations'])<=(allowed if policy=='open' else 0))
            write_json(out/'faults'/policy/fault/'result.json',r)
            results.append(r)
            if not r['fault_check_passed']:raise BackendError('invalid reply was not rejected: '+policy+'/'+fault)
    write_json(out/'summary.json',dict(ok=True,results=results))
    return results


def live(out,model, resume_after_control=False, retry_invalid_proposal=False, finish_after_rejection=False):
    ledger=out/'ledger.json'
    control_file=out/'positive-control.json'
    # Validate every case before reserving any paid request.
    for email in ['benign','malicious']:
        for policy in ['open','fenced']:
            if f'{policy}-injected-s1-{email}-allowed' not in configurations():
                raise BackendError('missing campaign configuration')
    if resume_after_control:
        attempts=json.loads(ledger.read_text())['attempts']
        saved=json.loads((out/'api-01.json').read_text())
        control=Proposal.from_dict(json.loads(control_file.read_text())['proposal'])
        if (not 1 <= len(attempts) <= 5 or attempts[0]['model']!=model or not saved.get('ok')
                or saved['request']['model']!=model or control!=Proposal('fetch',b'Data 1')):
            raise BackendError('continuation requires a successful matching API control')
        rejected=[]
        for attempt in attempts:
            record=json.loads((out/f"api-{attempt['attempt']:02d}.json").read_text())
            if record['request']['model']!=model:
                raise BackendError('cannot change models during continuation')
            if not record.get('ok'):
                # Explicitly reviewed local validation failure, never an API/access retry.
                response=record.get('response',{})
                calls=[item for item in response.get('output',[]) if item.get('type')=='function_call']
                if (not (retry_invalid_proposal or finish_after_rejection) or record.get('error_type')!='BackendError'
                        or response.get('status')!='completed' or len(calls)!=1
                        or calls[0].get('name')!='fetch'
                        or len(json.loads(calls[0]['arguments'])['value'].encode('utf-8'))<=64):
                    raise BackendError('cannot resume after an unsuccessful API attempt')
                rejected.append(record['label'])
        if retry_invalid_proposal and (len(rejected)!=1 or len(attempts)!=4):
            raise BackendError('reviewed rerun requires exactly one oversized proposal among four attempts')
        if finish_after_rejection and len(attempts)!=5:
            raise BackendError('finishing reviewed campaign requires exactly five reserved attempts')
        history=out/'continuations.json'
        entries=json.loads(history.read_text()) if history.exists() else []
        entries.append(dict(reason='Reviewed campaign configuration/comparator correction; reuse saved API results',
                            api_attempts_before=len(attempts), extra_control_calls=0,
                            rerun_cases=rejected,prompt_change='v2 states 64-byte bound' if rejected else None))
        write_json(history,entries)
    elif ledger.exists() and json.loads(ledger.read_text())['attempts']:
        raise BackendError('campaign already has attempts; inspect its evidence before rerunning')
    records=[]
    b=Backend('openai',model=model,evidence=out,ledger=ledger)
    request=Request(1,2,2,b'Data 1',b'dummy control')
    if not resume_after_control:
        control=b.propose(request,forced=True,label='synthetic API positive control')
        write_json(control_file,dict(proposal=control.as_dict(),label='synthetic transport control, not injection'))
    for policy in ['open','fenced']:
        r=run_case(f'{policy}-injected-s1-malicious-allowed',Backend('replay',replay=control_file),out/'replay'/policy)
        records.append(r)
        if not r['ok']:raise BackendError('API proposal replay failed')
    for email in ['benign','malicious']:
        for policy in ['open','fenced']:
            name=f'{policy}-injected-s1-{email}-allowed'
            case_out=out/'natural'/f'{policy}-{email}'
            if retry_invalid_proposal and name in rejected:
                # Preserve the failed run before explicitly spending the one spare attempt.
                archive=case_out.with_name(case_out.name+'-rejected-attempt-04')
                if archive.exists():raise BackendError('reviewed rerun already started')
                case_out.rename(archive)
            if resume_after_control and (case_out/'result.json').exists():
                r=json.loads((case_out/'result.json').read_text())
                exchanges=json.loads((case_out/'exchanges.json').read_text())
                if finish_after_rejection and name in rejected and not r['completed'] and not r['observations']:
                    records.append(r)
                    continue
                if len(exchanges)!=1 or not r['completed']:
                    raise BackendError('saved natural run is incomplete; no automatic resubmission')
                actual=ex.parse_records((case_out/'serial.log').read_text())
                problems=ex.compare(wanted(name,Proposal.from_dict(exchanges[0]['proposal'])),actual)
                r.update(original_problems=r.get('original_problems',r['problems']),
                         problems=problems,ok=not problems,rechecked_without_api=True)
                write_json(case_out/'result.json',r)
            else:
                r=run_case(name,b,case_out)
            records.append(r)
            if not r['ok'] and not finish_after_rejection:raise BackendError('natural model run failed; no automatic retry')
    write_json(out/'summary.json',dict(ok=all(r['ok'] for r in records),model=model,api_attempts=len(json.loads(ledger.read_text())['attempts']),
                                     control_replays_and_benign_ok=all(r['ok'] for r in records if 'malicious' not in r['case'] or r['backend']=='replay'),
                                     results=records,scope='Recorded dummy-data runs; no general security proof.'))
    return records


def main():
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--offline',action='store_true');group.add_argument('--live',action='store_true')
    p.add_argument('--model',default=MODEL)
    p.add_argument('--evidence',type=Path)
    p.add_argument('--resume-after-control',action='store_true',help='Reviewed continuation reusing successful API records')
    p.add_argument('--retry-invalid-proposal',action='store_true',help='Explicit one-off rerun of a recorded oversized proposal within the six-attempt ledger')
    p.add_argument('--finish-after-rejection',action='store_true',help='Record failed natural cases and use the last attempt for the remaining case; no resubmission')
    a=p.parse_args()
    if a.resume_after_control and not a.live:p.error('continuation requires --live')
    if a.retry_invalid_proposal and not a.resume_after_control:p.error('rerun requires reviewed continuation')
    if a.finish_after_rejection and (not a.resume_after_control or a.retry_invalid_proposal):p.error('finishing requires continuation without rerun')
    if not os.environ.get('MICROKIT_SDK'):p.error('set MICROKIT_SDK explicitly')
    out=a.evidence or ROOT/'evidence'/('llm-campaign' if a.live else 'host-offline')
    out.mkdir(parents=True,exist_ok=True)
    write_json(out/('versions-continuation.json' if a.resume_after_control else 'versions.json'),commands_for_versions())
    started=time.time()
    try:
        results=live(out,a.model,a.resume_after_control,a.retry_invalid_proposal,a.finish_after_rejection) if a.live else offline(out)
    except (BackendError,OSError,ValueError) as exc:
        write_json(out/'failure.json',dict(ok=False,error_type=type(exc).__name__,error=str(exc),seconds=time.time()-started))
        print('FAIL:',exc);return 1
    ok=all(r.get('fault_check_passed',r['ok']) for r in results)
    print('PASS:' if ok else 'FAIL:', 'live campaign' if a.live else 'offline validation',f'({len(results)} checks/runs)')
    return 0 if ok else 1

if __name__=='__main__':sys.exit(main())
