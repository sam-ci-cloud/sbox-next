"""Read-only official sing-box V2Ray StatsService client over authenticated local HTTP/2.
Wire fields are defined by pinned upstream experimental/v2rayapi/stats.proto.
No reset RPC, arbitrary RPC path or remote address is exposed to the WebUI.
"""
import socket,struct,time
from pathlib import Path
from common import Problem,require

def varint(data,pos):
 value=0
 for shift in range(0,70,7):
  require(pos<len(data),'Truncated stats protobuf',503);n=data[pos];pos+=1;value|=(n&127)<<shift
  if n<128:return value,pos
 raise Problem(503,'Oversized stats varint')
def fields(data):
 pos=0
 while pos<len(data):
  key,pos=varint(data,pos);kind=key&7
  if kind==0:value,pos=varint(data,pos)
  elif kind==2:
   length,pos=varint(data,pos);require(length<=4*1024*1024 and pos+length<=len(data),'Invalid stats field length',503);value=data[pos:pos+length];pos+=length
  elif kind in [1,5]:size=8 if kind==1 else 4;value=data[pos:pos+size];pos+=size
  else:raise Problem(503,'Unsupported stats wire type')
  yield key>>3,value

def query(port=25001,key_file='/etc/sbox-manager/stats-auth.key',allow_unsecured_lab=False):
 try:
  import h2.connection,h2.config,h2.events
 except ImportError:raise Problem(503,'Install the distribution python3-h2 package for authenticated accounting')
 require(type(port) is int and 1024<=port<=65535,'Invalid local stats port',503)
 secret=Path(key_file).read_text().strip() if key_file else ''
 require(secret or allow_unsecured_lab,'Stats authorization key is unavailable',503)
 conn=h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True,header_encoding='utf-8'));conn.initiate_connection()
 headers=[(':method','POST'),(':scheme','http'),(':authority','127.0.0.1:'+str(port)),(':path','/v2ray.core.app.stats.command.StatsService/QueryStats'),('content-type','application/grpc'),('te','trailers'),('grpc-timeout','3S')]
 if secret:headers.append(('authorization','Bearer '+secret))
 conn.send_headers(1,headers);conn.send_data(1,b'\0'+struct.pack('!I',0),end_stream=True);raw=bytearray();status=None;http=None
 with socket.create_connection(('127.0.0.1',port),timeout=3) as sock:
  sock.sendall(conn.data_to_send());done=False;started=time.monotonic()
  while not done:
   require(time.monotonic()-started<4,'Stats RPC exceeded time limit',503);data=sock.recv(65536);require(data,'Stats RPC disconnected',503)
   for event in conn.receive_data(data):
    if isinstance(event,(h2.events.ResponseReceived,h2.events.TrailersReceived)):
     for key,value in event.headers:
      if key=='grpc-status':status=value
      if key==':status':http=value
    elif isinstance(event,h2.events.DataReceived):
     raw.extend(event.data);require(len(raw)<=4*1024*1024,'Stats response is oversized',503);conn.acknowledge_received_data(event.flow_controlled_length,event.stream_id)
    elif isinstance(event,h2.events.StreamEnded):done=True
    elif isinstance(event,(h2.events.StreamReset,h2.events.ConnectionTerminated)):raise Problem(503,'Stats RPC was rejected')
   pending=conn.data_to_send()
   if pending:sock.sendall(pending)
 require(http=='200' and status=='0','Stats RPC authorization/service unavailable',503)
 require(len(raw)>=5 and raw[0]==0 and struct.unpack('!I',raw[1:5])[0]==len(raw)-5,'Invalid stats response envelope',503)
 result={}
 for key,entry in fields(raw[5:]):
  if key!=1:continue
  row=dict(fields(entry));name=row.get(1,b'').decode('utf-8');value=row.get(2,0)
  require(isinstance(value,int) and 0<=value<2**63 and len(name)<=256,'Invalid stats counter',503)
  require(name not in result,'Duplicate stats counter',503);result[name]=value
 return result
