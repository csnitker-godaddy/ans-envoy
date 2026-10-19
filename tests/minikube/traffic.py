"""Local-only ANS-6 conformance probes. Uses public demo TL material, never production keys."""
import argparse,base64,copy,gzip,hashlib,http.client,json,os,ssl,time,uuid
from pathlib import Path
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,utils
B=Path(os.environ['ANS_ENVOY_TEST_DIR']).resolve()
ANS='ans://v1.0.0.caller.example.com'
AGENT='7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07'
ORIGIN='https://agent.example.com'
TL=ec.derive_private_key(int.from_bytes(bytes([0x11])*32,'big'),ec.SECP256R1())
def b64(x):return base64.b64encode(x).decode()
def b64url(x):return base64.urlsafe_b64encode(x).decode().rstrip('=')
def sign(key,content):
 r,s=utils.decode_dss_signature(key.sign(content,ec.ECDSA(hashes.SHA256())))
 return r.to_bytes(32,'big')+s.to_bytes(32,'big')
KEY=serialization.load_der_private_key((B/'bundle/caller.key.pk8').read_bytes(),None)
CERT=(B/'bundle/caller.cert.der').read_bytes()
MTLS_KEY=serialization.load_pem_private_key((B/'tls/client.key').read_bytes(),None)
MTLS_CERT=(B/'tls/client.der').read_bytes()
TOKEN=(B/'bundle/status-token.b64').read_text().strip()
RECEIPT=(B/'bundle/receipt.b64').read_text().strip()

def proof(body=b'',path='/api/task',method='POST',origin=ORIGIN,key=KEY,cert=CERT,payload_change=None,header_change=None):
 n=key.public_key().public_numbers()
 header={'typ':'dpop+jwt','alg':'ES256','jwk':{'kty':'EC','crv':'P-256','x':b64url(n.x.to_bytes(32,'big')),'y':b64url(n.y.to_bytes(32,'big'))},'x5c':[b64(cert)]}
 payload={'htm':method,'htu':origin+path,'iat':int(time.time()),'jti':str(uuid.uuid4()),'ans_profile':1,'ans_content_digest':b64url(hashlib.sha256(body).digest())}
 if payload_change:payload_change(payload)
 if header_change:header_change(header)
 wire=b64url(json.dumps(header,separators=(',',':')).encode())+'.'+b64url(json.dumps(payload,separators=(',',':')).encode())
 return wire+'.'+b64url(sign(key,wire.encode()))

def artifact(encoded,change,status=True):
 obj=cbor2.loads(base64.b64decode(encoded))
 payload=cbor2.loads(obj[2]) if status else json.loads(obj[2])
 change(payload)
 obj[2]=cbor2.dumps(payload) if status else json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
 obj[3]=sign(TL,cbor2.dumps(['Signature1',obj[0],b'',obj[2]]))
 return b64(cbor2.dumps(obj))

def for_cert(cert,**kwargs):
 def update(p):
  p[6][0][1]=hashlib.sha256(cert).digest()
  for k,v in kwargs.items():p[int(k)]=v
 return artifact(TOKEN,update)
MTLS_TOKEN=for_cert(MTLS_CERT)

def context(mtls=False):
 c=ssl.create_default_context(cafile=str(B/'tls/ca.crt'))
 if mtls:c.load_cert_chain(str(B/'tls/client.crt'),str(B/'tls/client.key'))
 return c

def request(port=28443,p=None,body=b'',path='/api/task',method='POST',token=TOKEN,receipt=RECEIPT,extra=(),mtls=False,chunked=False,host="agent.example.com"):
 c=http.client.HTTPSConnection('127.0.0.1',port,context=context(mtls),timeout=10)
 try:
  c.putrequest(method,path,skip_host=True,skip_accept_encoding=True)
  c.putheader('Host',host)
  if p is not None:c.putheader('DPoP',p)
  if token is not None:c.putheader('X-ANS-Status-Token',token)
  if receipt is not None:c.putheader('X-SCITT-Receipt',receipt)
  for k,v in extra:c.putheader(k,v)
  if chunked:
   c.putheader('Transfer-Encoding','chunked')
   wire=(f'{len(body):X}\r\n'.encode()+body+b'\r\n0\r\n\r\n') if body else b'0\r\n\r\n'
  else:
   c.putheader('Content-Length',str(len(body)));wire=body
  c.endheaders(wire)
  r=c.getresponse();data=r.read();headers=dict((k.lower(),v) for k,v in r.getheaders())
  try:payload=json.loads(data)
  except (ValueError,UnicodeDecodeError):payload=None
  return {'status':r.status,'label':headers.get('x-ans-deny-label'),'body':payload}
 finally:c.close()

def count():
 c=http.client.HTTPConnection('127.0.0.1',28080,timeout=5)
 try:
  c.request('GET','/__test_count');r=c.getresponse();return json.loads(r.read())['count']
 finally:c.close()
RESULTS=[]
def case(name,status,label=None,verify=None,**kwargs):
 before=count()
 try:
  r=request(**kwargs);delta=count()-before
  ok=r['status']==status and (label is None or r['label']==label) and delta==(1 if status==200 else 0)
  if verify:ok=ok and bool(verify(r))
  row={'name':name,'pass':ok,'expected_status':status,'status':r['status'],'expected_label':label,'label':r['label'],'upstream_requests':delta}
 except Exception as e:
  row={'name':name,'pass':False,'error':str(e)}
 RESULTS.append(row);print(('PASS' if row['pass'] else 'FAIL')+' '+name+' '+json.dumps(row),flush=True)
 return row

def run_matrix():
 p=proof();case('valid empty Method B',200,p=p,verify=lambda r:r['body']['caller']['x-ans-caller-ans-name']==ANS)
 case('cross-replica replay',401,'REPLAY',port=28444,p=p)
 case('fresh proof through second replica',200,port=28444,p=proof())
 case('no credential',401,'NO_CREDENTIAL')
 case('missing status token',401,'MISSING_HEADERS',p=proof(),token=None)
 case('missing receipt',401,'MISSING_HEADERS',p=proof(),receipt=None)
 for h,value in [('DPoP',proof()),('X-ANS-Status-Token',TOKEN),('X-SCITT-Receipt',RECEIPT)]:
  case('duplicate '+h,401,'DUPLICATE_HEADER',p=proof(),extra=[(h,value)])
 case('duplicate Authorization',401,'DUPLICATE_HEADER',p=proof(),extra=[('Authorization','DPoP token'),('Authorization','DPoP token')])
 merged='token,DPoP token'
 case('duplicate Authorization with matching merged ath',401,'DUPLICATE_HEADER',p=proof(payload_change=lambda p:p.update(ath=b64url(hashlib.sha256(merged.encode()).digest()))),extra=[('Authorization','DPoP token'),('Authorization','DPoP token')])
 case('duplicate Bearer credentials',401,'DUPLICATE_HEADER',p=proof(),extra=[('Authorization','Bearer one'),('Authorization','Bearer two')])
 case('single DPoP token remains valid',200,p=proof(payload_change=lambda p:p.update(ath=b64url(hashlib.sha256(b'token').digest()))),extra=[('Authorization','DPoP token')])
 case('wrong origin with spoofed Host',401,'HTTP_BINDING_MISMATCH',p=proof(origin='https://other.example.com'),host='other.example.com',extra=[('x-forwarded-host','other.example.com')])
 case('wrong method',401,'HTTP_BINDING_MISMATCH',p=proof(),method='DELETE')
 case('wrong path',401,'HTTP_BINDING_MISMATCH',p=proof(path='/different'))
 for path in ['/a/../api/task','/a/%2e%2e/api/task','/api%2ftask']:
  case('raw path preserved '+path,200,p=proof(path=path),path=path,verify=lambda r:r['body']['path']==path)
 case('dot segments do not alias',401,'HTTP_BINDING_MISMATCH',p=proof(path='/a/../api/task'))
 case('escape case does not alias',401,'HTTP_BINDING_MISMATCH',p=proof(path='/api%2ftask'),path='/api%2Ftask')
 for name,body,extra in [('ASCII',b'{"amount":100}',[]),('binary',bytes(range(256)),[]),('gzip',gzip.compress(b'content remains encoded'),[('Content-Encoding','gzip')])]:
  case(name+' content intact',200,p=proof(body),body=body,extra=extra,verify=lambda r,b=body:r['body']['sha256']==hashlib.sha256(b).hexdigest())
 case('chunked transfer preserves digest',200,p=proof(b'chunked content'),body=b'chunked content',chunked=True)
 p=proof(b'bound body');case('altered body',401,'CONTENT_BINDING_MISMATCH',p=p,body=b'tampered')
 case('failed content check does not spend proof',200,p=p,body=b'bound body')
 case('body added to empty request',401,'CONTENT_BINDING_MISMATCH',p=proof(),body=b'added')
 case('body removed',401,'CONTENT_BINDING_MISMATCH',p=proof(b'removed'))
 for name,change in [('missing digest',lambda p:p.pop('ans_content_digest')),('malformed digest',lambda p:p.update(ans_content_digest='bad')),('null profile',lambda p:p.update(ans_profile=None))]:
  case(name,401,'MALFORMED_PROOF',p=proof(payload_change=change))
 case('unsupported profile',401,'UNSUPPORTED_PROFILE',p=proof(payload_change=lambda p:p.update(ans_profile=2)))
 case('absent profile selects revision one',200,p=proof(payload_change=lambda p:p.pop('ans_profile')))
 case('unknown payload claim tolerated',200,p=proof(payload_change=lambda p:p.update(future_claim='ignored')))
 case('unknown protected header rejected',401,'MALFORMED_PROOF',p=proof(header_change=lambda h:h.update(kid='forbidden')))
 case('expired proof',401,'PROOF_STALE',p=proof(payload_change=lambda p:p.update(iat=int(time.time())-600)))
 expired=artifact(TOKEN,lambda p:p.update({3:int(time.time())-7200,4:int(time.time())-3600}))
 case('expired status token',401,'STATUS_INVALID',p=proof(),token=expired)
 revoked=artifact(TOKEN,lambda p:p.update({2:'REVOKED'}))
 case('revoked registration',401,'STATUS_INVALID',p=proof(),token=revoked)
 case('invalid supplied receipt',401,'RECEIPT_INVALID',p=proof(),receipt=b64(b'invalid COSE'))
 wrong=artifact(RECEIPT,lambda p:p['payload']['producer']['event'].update(ansName='ans://v2.0.0.caller.example.com'),status=False)
 case('receipt version mismatch',401,'BINDING_FAILED',p=proof(),receipt=wrong)
 case('spoofed upstream identity replaced',200,p=proof(),extra=[('x-ans-caller-ans-name','attacker'),('x-ans-caller-agent-id','attacker'),('x-ans-caller-method','attacker'),('x-ans-caller-jkt','attacker')],verify=lambda r:r['body']['caller']['x-ans-caller-ans-name']==ANS and r['body']['caller']['x-ans-caller-agent-id']==AGENT and r['body']['caller']['x-ans-caller-method']=='method_b' and r['body']['caller']['x-ans-caller-jkt']!='attacker')
 large=b'x'*(1048576+1)
 case('oversize body rejected by Envoy',413,p=proof(large),body=large)
 case('valid Method A with private test CA',200,mtls=True,token=MTLS_TOKEN,verify=lambda r:r['body']['caller']['x-ans-caller-method']=='method_a' and 'x-ans-caller-jkt' not in r['body']['caller'])
 case('Method A missing receipt',401,'MISSING_HEADERS',mtls=True,token=MTLS_TOKEN,receipt=None)
 case('Method A wrong certificate fingerprint',401,'BINDING_FAILED',mtls=True,token=TOKEN)
 wrong_token=artifact(MTLS_TOKEN,lambda p:p.update({5:'ans://v2.0.0.caller.example.com'}))
 case('Method A full-name version mismatch',401,'BINDING_FAILED',mtls=True,token=wrong_token,receipt=wrong)
 case('Method A receipt version mismatch',401,'BINDING_FAILED',mtls=True,token=MTLS_TOKEN,receipt=wrong)
 case('Method A bad receipt',401,'RECEIPT_INVALID',mtls=True,token=MTLS_TOKEN,receipt=b64(b'invalid COSE'))
 case('DPoP wins when mTLS also present',200,p=proof(),mtls=True,verify=lambda r:r['body']['caller']['x-ans-caller-method']=='method_b')

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--mode',choices=['matrix','redis-outage','recovery'],default='matrix');args=parser.parse_args()
 if args.mode=='matrix':run_matrix()
 elif args.mode=='redis-outage':case('Redis unavailable fails closed',500,'REPLAY_CACHE_UNAVAILABLE',p=proof())
 else:case('authorizer recovers after Redis restart',200,p=proof())
 result={'mode':args.mode,'passed':sum(r['pass'] for r in RESULTS),'total':len(RESULTS),'results':RESULTS}
 (B/f'{args.mode}-results.json').write_text(json.dumps(result,indent=2)+'\n')
 print(f"{result['passed']}/{result['total']} checks passed",flush=True)
 raise SystemExit(0 if result['passed']==result['total'] else 1)
