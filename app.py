import argparse
import json
from urllib.parse import quote
from urllib.request import Request, urlopen
from common import serve

TYPES = ['A', 'AAAA', 'MX', 'TXT', 'CAA']

def query(host, record_type):
    url = f'https://cloudflare-dns.com/dns-query?name={quote(host)}&type={record_type}'
    req = Request(url, headers={'Accept': 'application/dns-json', 'User-Agent': 'defensive-dns-checker/1.0'})
    with urlopen(req, timeout=6) as response:
        data = json.load(response)
    return [answer.get('data', '') for answer in data.get('Answer', [])]

def analyze(values):
    host = values.get('host', '').strip().rstrip('.')
    if not host or len(host) > 253 or '://' in host or any(ch.isspace() for ch in host):
        return {'error': 'Enter one hostname, not a URL.'}
    records = {rtype: query(host, rtype) for rtype in TYPES}
    dmarc = query('_dmarc.' + host, 'TXT')
    spf = [value for value in records['TXT'] if 'v=spf1' in value.lower()]
    return {'hostname': host, 'records': records, 'spf_records': spf, 'dmarc_records': dmarc, 'review': 'Presence of SPF/DMARC/C AA records is a starting point; policy quality requires organizational context.'}

def main():
    parser = argparse.ArgumentParser(description='Review DNS records for one authorized hostname.')
    parser.add_argument('host', nargs='?'); parser.add_argument('--web', action='store_true'); parser.add_argument('--port', type=int, default=8082)
    args = parser.parse_args()
    if args.web: serve('DNS Security Checker', [('host','Hostname','text','example.com')], analyze, args.port)
    elif args.host: print(json.dumps(analyze({'host':args.host}), indent=2))
    else: parser.print_help()

if __name__ == '__main__': main()
