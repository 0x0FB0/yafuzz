import argparse
import requests
import re
import sys
import threading
import logging
import zlib
import time
import traceback

logging.basicConfig(format='%(message)s')
LOGGER = logging.getLogger()

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERBOSE = False
WORDLIST = None
TAG = '[INJECT]'

def parse_headers(headers):
    valid = {}
    try:
        for h in headers:
            if type(h) == str and ':' in h:
                valid.update({h.split(':')[0]: h.split(':')[1].strip()})
        log("info", "Got headers: %s" % repr(valid))
        get_content_type(valid)
        return valid
    except Exception as e:
        log("error", "Invalid header format!\n%s"+repr(e))
        raise argparse.ArgumentTypeError
    
def parse_cookies(cookies):
    valid = {}
    try:
        for c in cookies:
            if type(c) == str and '=' in c:
                key = c.split('=')[0]
                value = '='.join(
                    [c for c in c.split("=")[1:]]
                    )
                valid.update({ key: value})
        log("info", "Got cookies: %s" % repr(valid))
        return valid
    except Exception as e:
        log("error", "Invalid cookie format!\n%s"+repr(e))
        raise argparse.ArgumentTypeError
    
def parse_wordlist(wordlist):
    if wordlist:
        with open(args.wordlist, 'r') as f:
                wordlist = f.read().split('\n')
                return wordlist
    else:
        return False
    
def log(ltype, lmessage):
    codes = {
        'ok': '\033[32m[+] ',
        'error': '\033[31m[!] ',
    }
    endcolor = '\033[0m'
    global VERBOSE
    if ltype in codes.keys():
        LOGGER.warning(codes[ltype] + lmessage + endcolor)
    elif VERBOSE:
        LOGGER.info('[i] ' + lmessage + endcolor)
        
    
def get_content_type(headers):
    content_type = 'application/x-www-form-urlencoded'
    headers_lower = dict((k.lower(), v) for k,v in {'My Key':'My Value'}.items())
    if 'content-type' in headers_lower:
        content_type = headers_lower['content-type']
    log("info", "Got Content-Type: %s" % content_type)
    return content_type

def send_http(specs, method):
    response = requests.request(
        method.upper(),
        specs['url'],
        headers=specs['headers'],
        cookies=specs['cookies'],
        data=specs['data'],
        allow_redirects=specs['redirect'],
        timeout=int(specs['timeout']),
        proxies=specs['proxy'],
        verify=False
        )
    return response

def inject(specs_orig, payload):
    injectable = ["url", "data", "headers", "cookies"]
    specs = specs_orig.copy()
    def handle_dict(k, d, p):
        dspec = d.copy()
        for dkey in d:
            if TAG in dkey:
                log("info", "Replacing in %s" % k)
                newk = dkey.replace(TAG, p)
                dspec[newk] = d[dkey]
            if TAG in dspec[dkey]:
                log("info", "Replacing in %s" % k)
                dspec[dkey] = d[dkey].replace(TAG, p)
        return dspec
    for skey in injectable:
        if type(specs[skey]) == str and TAG in specs[skey]:
            log("info", "Replacing in %s" % skey)
            specs[skey] = specs[skey].replace(TAG, payload)
        if type(specs[skey]) == dict:
            specs[skey] = handle_dict(skey, specs[skey], payload)
    return specs
        
def fuzz(payload, specs, method):
    try:
        banned = specs['banned']
        specs_injected = inject(specs, payload)
        start_t = time.time()
        response = send_http(specs_injected, method)
        took_t = "{:.3f}".format(time.time() - start_t)
        parse_response(response, specs['extract'], payload, method, banned, took_t)
    except Exception as e:
        log("error", "Failed on at %s %s: %s" % (method, payload, str(e)))
        if VERBOSE:
            log("error", traceback.format_exc())
        
        
def inline_tamper(specs):
    while True:
        payload = input("> ")
        for method in specs['method']:
            fuzz(payload, specs, method)

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]        

def wordlist_tamper(specs):
    threads = []
    chunkl = chunks(WORDLIST, int(specs['speed']))
    for chunk in chunkl:
        for word in chunk:
            for method in specs['method']:
                bt = threading.Thread(target=fuzz, args=(word, specs, method))
                bt.daemon = False
                threads.append(bt)
                bt.start()
        for a,b in enumerate(threads):
            b.join()
        
def parse_response(res, ext, pld, method, banned, took_t):
    headers_raw = '\r\n'.join('{}: {}'.format(k, v) for k, v in res.headers.items())
    res_raw = "HTTP/1.1 %s %s (took: %ss)\n%s\n%s" % (
        str(res.status_code),
        res.reason,
        took_t,
        headers_raw,
        '\r\n\r\n'+res.content.decode('utf-8')
        )
    status_code_banned = False
    h_hash = str(zlib.crc32(headers_raw.encode('utf-8')))
    b_hash = str(zlib.crc32(res.content))
    for b in banned:
        if len(b) == 3 and b == str(res.status_code):
            status_code_banned = True
    show = h_hash not in banned and b_hash not in banned and not status_code_banned
    
    match = re.findall(ext, res_raw, re.MULTILINE) if ext else False
    if match and len(match) > 0:
        if type(match[0]) == tuple:
            match = list(match[0]) 
    
    if ext:
        if match and show:
            log('ok', "Sent: %s %s\n[+] Received after %ss: %s" % (method, pld, took_t, ', '.join(match)))
    else:
        if VERBOSE and show:
            spacer = '-'*50
            log('ok', "Sent: %s %s\n[+] Received after %ss: \r\n%s\r\n%s\r\n%s\r\n" % (
                method, pld, took_t, spacer, res_raw, spacer
                ))
        elif show:
            log('ok', "Sent: %s %s\n[+] Received after %ss code: %s\theaders:\t%s\tbody:\t%s" % (
                method,
                pld,
                took_t,
                str(res.status_code),
                h_hash,
                b_hash
            ))
            
def parse_methods(methods):
    if len(methods) > 1:
        methods.remove('GET')
    return list(set(methods))
            

def handle_requests(requests_specs):
    for key, value in requests_specs.items():
        log("info", "Got %s spec: %s" % (key, repr(value)))
    if WORDLIST != None:
        log("info", "Got wordlist length: %s" % len(WORDLIST))
        log("ok", "Starting wordlist bruteforce mode")
        wordlist_tamper(requests_specs)
    else:
        log("ok", "Starting inline tampering mode")
        try:
            inline_tamper(requests_specs)
        except (KeyboardInterrupt, EOFError) as e:
            print("\n")
            log("ok", "Bye.")
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Yet another HTTP fuzzer")
    parser.add_argument('--url','-U', help='Target HTTP URL address', required=True) 
    parser.add_argument('--wordlist','-W', help='Wordlist file path')
    parser.add_argument('--extract','-E', help='RegEx pattern to extract from response')
    parser.add_argument('--ban','-B', help='Ban specific crc32 hash or response code from output', default=['none'], action='append', dest='banned')
    parser.add_argument('--header','-H', help='HTTP Headers i.e. "TEST: true"', action='append', dest='headers')
    parser.add_argument('--cookie','-C', help='HTTP Cookies i.e. "TEST=true"', action='append', dest='cookies')
    parser.add_argument('--data','-D', help='HTTP request body', default='\r\n')
    parser.add_argument('--speed','-S', help='Number of threads', default='10')
    parser.add_argument('--method','-M', help='HTTP method to use', default=["GET"], action='append')
    parser.add_argument('--tag','-T', help='Tag to search for and replace', default="[INJECT]")
    parser.add_argument('--redirect','-R', help='Accept HTTP redirects', action='store_true', default=False)
    parser.add_argument('--timeout','-O', help='Timeout of the HTTP request', default='10')
    parser.add_argument('--verbose','-V', help='Enable verbose output', action='store_true', default=False)
    parser.add_argument('--proxy','-X', help='Enable HTTP proxy')
    args = parser.parse_args()
    try:
        VERBOSE = args.verbose
        WORDLIST = parse_wordlist(args.wordlist) if args.wordlist else None
        TAG = args.tag
        
        requests_specs = {
            "url": args.url,       
            "extract": args.extract,
            "headers": parse_headers(args.headers) if args.headers else {},
            "cookies": parse_cookies(args.cookies) if args.cookies else {},
            "data": args.data,
            "method": parse_methods(args.method),
            "redirect": args.redirect,
            "timeout": args.timeout,
            "banned": args.banned,
            "speed": args.speed,
            "proxy": {'all': args.proxy} if args.proxy and re.match('https*://.+', args.proxy) else {}
        }
    except Exception as e:
        log("error", repr(e))
        parser.print_help()
        sys.exit(1)
        
    
    handle_requests(requests_specs)
    
