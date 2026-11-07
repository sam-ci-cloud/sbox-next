"""Pure quota policy/calendar model, shared by manager validation and collector."""
import calendar
import datetime as _qd
from decimal import Decimal,InvalidOperation
import re as _qr
from zoneinfo import ZoneInfo,ZoneInfoNotFoundError

QUOTA_KEYS={'quota_bytes','period','timezone','reset_day','expires_at','manual_disabled','reset_seq'}

def quota_size(value):
 if type(value) is int:
  if 0<=value<=10**15:return value
  raise ValueError('Quota must be between 0 (unlimited) and 1 PB')
 if not isinstance(value,str):raise ValueError('Use a byte integer or an explicit size such as 5 GiB')
 m=_qr.fullmatch(r'\s*(\d+(?:\.\d{1,6})?)\s*(B|KB|KiB|MB|MiB|GB|GiB|TB|TiB)\s*',value,_qr.I)
 if not m:raise ValueError('Size needs an explicit B/KB/KiB/MB/MiB/GB/GiB/TB/TiB unit')
 scale={'b':1,'kb':1000,'kib':1024,'mb':10**6,'mib':1024**2,'gb':10**9,'gib':1024**3,'tb':10**12,'tib':1024**4}[m[2].lower()];n=Decimal(m[1])*scale
 if n!=n.to_integral_value():raise ValueError('Quota must resolve to an integer number of bytes')
 return quota_size(int(n))

def quota_plan(value=None,base=None):
 if value is None:value={}
 if not isinstance(value,dict) or not set(value)<=QUOTA_KEYS:raise ValueError('Unknown quota field')
 result={'quota_bytes':0,'period':'monthly','timezone':'UTC','reset_day':1,'expires_at':0,'manual_disabled':False,'reset_seq':0}
 if base:result.update(base)
 result.update(value);result['quota_bytes']=quota_size(result['quota_bytes'])
 if result['period'] not in ('none','daily','weekly','monthly'):raise ValueError('Reset period must be none, daily, weekly or monthly')
 if not isinstance(result['timezone'],str) or len(result['timezone'])>64:raise ValueError('Invalid IANA timezone')
 try:ZoneInfo(result['timezone'])
 except (ZoneInfoNotFoundError,ValueError):raise ValueError('Unknown IANA timezone')
 if type(result['reset_day']) is not int or not 1<=result['reset_day']<=31:raise ValueError('Reset day must be 1–31')
 if result['period']=='weekly' and result['reset_day']>7:raise ValueError('Weekly reset day must be 1 (Monday)–7 (Sunday)')
 if type(result['expires_at']) not in (int,float) or not 0<=result['expires_at']<=4102444800:raise ValueError('Expiry must be a UTC Unix timestamp, or 0 for no expiry')
 if type(result['manual_disabled']) is not bool:raise ValueError('manual_disabled must be boolean')
 if type(result['reset_seq']) is not int or not 0<=result['reset_seq']<2**31:raise ValueError('Invalid reset sequence')
 return result

def quota_boundaries(now,plan):
 """Calendar reset boundaries in the configured IANA zone, returned as UTC epochs.
 Monthly anchor day is clamped per month, never progressively changed to Feb28.
 ZoneInfo's timestamp round trip chooses the first representable time after a
 missing local midnight; fold=0 chooses one occurrence for repeated midnights.
 """
 p=quota_plan(plan);zone=ZoneInfo(p['timezone']);dt=_qd.datetime.fromtimestamp(now,zone)
 def midnight(date):return _qd.datetime.combine(date,_qd.time(),zone).timestamp()
 if p['period']=='none':return (None,None)
 if p['period']=='daily':
  today=dt.date();return midnight(today),midnight(today+_qd.timedelta(days=1))
 if p['period']=='weekly':
  date=dt.date()-_qd.timedelta(days=(dt.isoweekday()-p['reset_day'])%7);return midnight(date),midnight(date+_qd.timedelta(days=7))
 def month(y,m):return midnight(_qd.date(y,m,min(p['reset_day'],calendar.monthrange(y,m)[1])))
 current=month(dt.year,dt.month)
 if now<current:
  y,m=(dt.year-1,12) if dt.month==1 else (dt.year,dt.month-1);return month(y,m),current
 y,m=(dt.year+1,1) if dt.month==12 else (dt.year,dt.month+1);return current,month(y,m)

def quota_status(user,used,now):
 p=quota_plan(user.get('quota'));expired=bool(p['expires_at'] and now>=p['expires_at']);exhausted=bool(p['quota_bytes'] and used is not None and used>=p['quota_bytes'])
 if not user.get('enabled',True) or p['manual_disabled']:return 'manually_disabled'
 if expired:return 'expired'
 if exhausted:return 'quota_exceeded'
 return 'active'
