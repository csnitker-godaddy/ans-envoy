"""Exercise only the disposable Redis deployment in the local validation namespace."""
import json,subprocess,time
import traffic as t
K=['kubectl','--kubeconfig',str(t.B/'kubeconfig'),'--context','minikube','-n','ans-envoy-validation']
def kubectl(*args):
 p=subprocess.run(K+list(args),text=True,capture_output=True,timeout=65)
 if p.returncode: raise RuntimeError(p.stderr or p.stdout)
 return p.stdout
proof=t.proof()
t.case('spend proof before Redis restart',200,p=proof)
try:
 kubectl('scale','deployment/redis','--replicas=0')
 kubectl('wait','--for=delete','pod','-l','app=redis','--timeout=45s')
 t.case('Redis outage fails closed',500,'REPLAY_CACHE_UNAVAILABLE',p=t.proof())
finally:
 kubectl('scale','deployment/redis','--replicas=1')
 kubectl('rollout','status','deployment/redis','--timeout=60s')
for port in [28443,28444]:
 for attempt in range(25):
  response=t.request(port=port,p=t.proof())
  if response['status']==200:break
  time.sleep(0.5)
 else:raise RuntimeError(f'authorizer on {port} did not recover after Redis returned')
 t.case(f'authorizer {port} recovered after Redis restart',200,port=port,p=t.proof())
t.case('spent proof remains rejected after Redis restart',401,'REPLAY',p=proof)
result={'passed':sum(x['pass'] for x in t.RESULTS),'total':len(t.RESULTS),'results':t.RESULTS}
(t.B/'resilience-results.json').write_text(json.dumps(result,indent=2)+'\n')
print(f"{result['passed']}/{result['total']} checks passed",flush=True)
raise SystemExit(0 if result['passed']==result['total'] else 1)
