"""Server-side form adapter: exact units and explicit IANA-local expiry."""
import datetime as dt
import time
from common import Problem,require
from quota_models import quota_plan,quota_boundaries
from usage_history import timezone

FIELDS={'amount','unit','unlimited','period','timezone','reset_day','no_expiry','expiry_local','expiry_fold','original_expires_at'}
UNITS=('B','KB','KiB','MB','MiB','GB','GiB','TB','TiB')


def preview(data,now=None):
 require(isinstance(data,dict) and set(data)<=FIELDS,'Unknown plan input field')
 require(type(data.get('unlimited')) is bool and type(data.get('no_expiry')) is bool,'Choose quota and expiry modes')
 name=data.get('timezone');zone=timezone(name);expiry=0
 if not data['no_expiry']:
  text=data.get('expiry_local','');require(isinstance(text,str) and len(text)<=32,'Invalid local expiry')
  try:
   local=dt.datetime.fromisoformat(text)
   require(local.tzinfo is None and 1970<=local.year<=2100,'Use a local expiry date without a UTC offset')
  except ValueError:raise Problem(422,'Choose a valid local expiry date and time') from None
  original=data.get('original_expires_at',0)
  require(type(original) in (int,float) and 0<=original<=4102444800,'Invalid existing expiry')
  # Preserve an existing exact instant (including seconds/fold) if its minute
  # display is untouched. This avoids silently truncating old expiry values.
  if original and dt.datetime.fromtimestamp(original,zone).strftime('%Y-%m-%dT%H:%M')==text:
   expiry=original
  else:
   candidates=sorted({local.replace(tzinfo=zone,fold=fold).timestamp() for fold in (0,1) if dt.datetime.fromtimestamp(local.replace(tzinfo=zone,fold=fold).timestamp(),zone).replace(tzinfo=None)==local})
   require(candidates,'This local time does not exist because the clock moves forward. Choose another time.',422)
   choice=data.get('expiry_fold','')
   require(choice in ('','earlier','later'),'Invalid repeated-time choice')
   if len(candidates)>1 and not choice:
    return {'requires_occurrence':True,'timezone':name,'occurrences':[{'choice':label,'utc':dt.datetime.fromtimestamp(value,dt.timezone.utc).isoformat(),'local':dt.datetime.fromtimestamp(value,zone).isoformat()} for label,value in zip(('earlier','later'),candidates)]}
   expiry=candidates[-1] if choice=='later' else candidates[0]
 require(data.get('unit') in UNITS,'Choose a quota unit')
 require(isinstance(data.get('amount'),str) and len(data['amount'])<=40,'Enter a numeric quota')
 period=data.get('period');day=data.get('reset_day',1)
 if period in ('daily','none'):day=1
 try:
  plan=quota_plan({'quota_bytes':0 if data['unlimited'] else data['amount']+' '+data['unit'],'period':period,'timezone':name,'reset_day':day,'expires_at':expiry})
  start,end=quota_boundaries(time.time() if now is None else now,plan)
 except ValueError as exc:raise Problem(422,str(exc)) from None
 return {'plan':{key:plan[key] for key in ('quota_bytes','period','timezone','reset_day','expires_at')},'canonical_bytes':str(plan['quota_bytes']),
         'period_start':start,'next_reset':end,'expires_utc':dt.datetime.fromtimestamp(expiry,dt.timezone.utc).isoformat() if expiry else None,
         'expires_local':dt.datetime.fromtimestamp(expiry,zone).isoformat() if expiry else None,'requires_occurrence':False}
