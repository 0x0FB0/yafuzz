# yafuzz
Yet another web fuzzer

![demo](yafuzz.gif)

---
## Usage
```
usage: yafuzz.py [-h] --url URL [--wordlist WORDLIST] [--extract EXTRACT]
                 [--ban BANNED] [--header HEADERS] [--cookie COOKIES]
                 [--data DATA] [--speed SPEED] [--method METHOD] [--tag TAG]
                 [--redirect] [--timeout TIMEOUT] [--verbose] [--proxy PROXY]

Yet another HTTP fuzzer

optional arguments:
  -h, --help            show this help message and exit
  --url URL, -U URL     Target HTTP URL address
  --wordlist WORDLIST, -W WORDLIST
                        Wordlist file path
  --extract EXTRACT, -E EXTRACT
                        RegEx pattern to extract from response
  --ban BANNED, -B BANNED
                        Ban specific crc32 hash or response code from output
  --header HEADERS, -H HEADERS
                        HTTP Headers i.e. "TEST: true"
  --cookie COOKIES, -C COOKIES
                        HTTP Cookies i.e. "TEST=true"
  --data DATA, -D DATA  HTTP request body
  --speed SPEED, -S SPEED
                        Number of threads
  --method METHOD, -M METHOD
                        HTTP method to use
  --tag TAG, -T TAG     Tag to search for and replace
  --redirect, -R        Accept HTTP redirects
  --timeout TIMEOUT, -O TIMEOUT
                        Timeout of the HTTP request
  --verbose, -V         Enable verbose output
  --proxy PROXY, -X PROXY
                        Enable HTTP proxy
```
