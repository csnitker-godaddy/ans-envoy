from pathlib import Path
from datetime import datetime,timedelta,timezone
import base64, hashlib, json, os, copy
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
R=Path(__file__).resolve().parents[2]
B=Path(os.environ['ANS_ENVOY_TEST_DIR']).resolve()
if B.is_relative_to(R): raise ValueError('Use a test directory outside the repository for private test keys')
IMAGE=os.environ['ANS_ENVOY_TEST_IMAGE']
NS='ans-envoy-validation'
os.umask(0o077)
(B/'tls').mkdir(exist_ok=True)
now=datetime.now(timezone.utc)
ca_key=ec.generate_private_key(ec.SECP256R1())
ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'ANS local integration test CA')])
ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False).add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True).sign(ca_key,hashes.SHA256()))
(B/'tls/ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
def issue(name,host,uris=(),client=False):
 key=ec.generate_private_key(ec.SECP256R1())
 import ipaddress
 sans=[x509.DNSName(host)]
 if not client: sans += [x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]
 sans += [x509.UniformResourceIdentifier(u) for u in uris]
 cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,host)])).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False).add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=False,decipher_only=False),critical=True).add_extension(x509.SubjectAlternativeName(sans),critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).sign(ca_key,hashes.SHA256()))
 (B/f'tls/{name}.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
 (B/f'tls/{name}.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
 (B/f'tls/{name}.der').write_bytes(cert.public_bytes(serialization.Encoding.DER))
issue('server','agent.example.com')
issue('client','caller.example.com',['ans://v1.0.0.caller.example.com'],client=True)
objects=[]
for file in sorted((R/'deploy/kubernetes/envoy').glob('*.yaml')):
 for obj in yaml.safe_load_all(file.read_text()):
  if obj is None: continue
  if obj['kind']=='Namespace': obj['metadata']['name']=NS
  else: obj['metadata']['namespace']=NS
  if obj['kind']=='ConfigMap' and obj['metadata']['name']=='ans-authz-config':
   value=obj['data']['ans-authz.toml'].replace('ans-demo.svc.cluster.local',NS+'.svc.cluster.local').replace('methods = "method_b"','methods = "both"').replace('replicas = 1','replicas = 2')
   value=value.replace('root_keys_url = "https://host.minikube.internal:8443/root-keys"','')
   value=value.replace('static_root_keys = []','static_root_keys = ['+json.dumps((B/'bundle/tl-root-keys.txt').read_text().strip())+']')
   obj['data']['ans-authz.toml']=value
   (B/'ans-authz.toml').write_text(value)
  if obj['kind']=='ConfigMap' and obj['metadata']['name']=='envoy-config':
   config=yaml.safe_load(obj['data']['envoy.yaml'])
   # Kubelet probes originate outside the pod; admin must be reachable at pod IP.
   config['admin']['address']['socket_address']['address']='0.0.0.0'
   fc=config['static_resources']['listeners'][0]['filter_chains'][0]
   fc['transport_socket']={'name':'envoy.transport_sockets.tls','typed_config':{'@type':'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext','require_client_certificate':False,'common_tls_context':{'tls_certificates':[{'certificate_chain':{'filename':'/etc/test-tls/server.crt'},'private_key':{'filename':'/etc/test-tls/server.key'}}],'validation_context':{'trusted_ca':{'filename':'/etc/test-tls/ca.crt'}}}}}
   fc['filters'][0]['typed_config']['http_filters'][0]['typed_config']['include_peer_certificate']=True
   value=yaml.safe_dump(config,sort_keys=False).replace('ans-demo.svc.cluster.local',NS+'.svc.cluster.local')
   obj['data']['envoy.yaml']=value
   (B/'envoy.yaml').write_text(value)
  if obj['kind']=='Deployment' and obj['metadata']['name']=='ans-gateway':
   for c in obj['spec']['template']['spec']['containers']:
    c['imagePullPolicy']='Never'
    if c['name']=='ans-authz': c['image']=IMAGE
    else:
     c['readinessProbe']['httpGet'].pop('host',None)
     c['volumeMounts'].append({'name':'test-tls','mountPath':'/etc/test-tls','readOnly':True})
   obj['spec']['template']['spec']['volumes'].append({'name':'test-tls','secret':{'secretName':'test-tls'}})
  if obj['kind']=='ConfigMap' and obj['metadata']['name']=='agent-script':
   obj['data']['agent.py']='''import hashlib,json,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
lock=threading.Lock()
count=0
class Handler(BaseHTTPRequestHandler):
 def _reply(self):
  global count
  if self.path=="/__test_count":
   with lock: data={"count":count}
  else:
   n=int(self.headers.get("content-length") or 0)
   content=self.rfile.read(n) if n else b""
   with lock:
    count+=1
    request_number=count
   data={"ok":True,"request_number":request_number,"received_bytes":len(content),"sha256":hashlib.sha256(content).hexdigest(),"path":self.path,"caller":{k.lower():v for k,v in self.headers.items() if k.lower().startswith("x-ans-caller-")}}
  body=json.dumps(data).encode()
  self.send_response(200)
  self.send_header("content-type","application/json")
  self.send_header("content-length",str(len(body)))
  self.end_headers()
  self.wfile.write(body)
 do_GET=do_POST=do_PUT=do_DELETE=do_PATCH=_reply
 def log_message(self,*args):pass
ThreadingHTTPServer(("0.0.0.0",8080),Handler).serve_forever()
'''
  if obj['kind']=='Deployment':
   for c in obj['spec']['template']['spec']['containers']: c['imagePullPolicy']='Never'
  if obj['kind']=='Service':
   obj['spec']['type']='ClusterIP'
   for p in obj['spec']['ports']: p.pop('nodePort',None)
  objects.append(obj)
objects.append({'apiVersion':'v1','kind':'Secret','metadata':{'name':'test-tls','namespace':NS},'type':'Opaque','data':{name:base64.b64encode((B/'tls'/name).read_bytes()).decode() for name in ['server.crt','server.key','ca.crt']}})
(B/'test-manifests.yaml').write_text(yaml.safe_dump_all(objects,sort_keys=False))
print(f'Prepared {len(objects)} resources in namespace {NS}; manifests/private test keys mode 0600')
