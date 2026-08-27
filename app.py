import argparse
import json
from urllib.parse import quote
from urllib.request import Request
from common import serve
from security_utils import bounded_read, open_no_redirect, validate_host

def query(host, record_type):
    url=f'https://cloudflare-dns.com/dns-query?name={quote(host,safe=".")}&type={record_type}'
    req=Request(url,headers={'Accept':'application/dns-json','User-Agent':'defensive-dns-checker/2.0'})
    with open_no_redirect(req,timeout=6) as response: return [answer.get('data','') for answer in json.loads(bounded_read(response).decode()).get('Answer',[])]

def analyze(values):
    try: host=validate_host(values.get('host',''),allow_private=values.get('_allow_private')=='1')
    except ValueError as exc: return {'error':str(exc)}
    try:
        records={rtype:query(host,rtype) for rtype in ('A','AAAA','MX','TXT','CAA')}; dmarc=query('_dmarc.'+host,'TXT')
        return {'hostname':host,'records':records,'spf_records':[v for v in records['TXT'] if 'v=spf1' in v.lower()],'dmarc_records':dmarc,'queries_made':6,'note':'Only fixed record types and the _dmarc label are queried. Presence is not proof of a correct policy.'}
    except Exception as exc: return {'error':f'DNS query failed: {type(exc).__name__}'}

def main():
    parser=argparse.ArgumentParser(description='Review DNS records for one authorized hostname.')
    parser.add_argument('host',nargs='?'); parser.add_argument('--allow-private',action='store_true'); parser.add_argument('--web',action='store_true'); parser.add_argument('--port',type=int,default=8082)
    args=parser.parse_args()
    if args.web: serve('DNS Security Checker',[('host','Hostname','text','example.com')],analyze,args.port)
    elif args.host: print(json.dumps(analyze({'host':args.host,'_allow_private':'1' if args.allow_private else '0'}),indent=2))
    else: parser.print_help()
if __name__=='__main__': main()
