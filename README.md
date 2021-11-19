# yafuzz
Yet another web fuzzer

## Usage

This script can run in two modes of operation.

Supplying a wordlist `-W` argument will initiate a multithreaded fuzzing session.

Lack of wordlist `-W` tag will run this script in interactive inline mode.

Use Burp Pro instead if you have one.

Key features:
- Fuzzer will replace all `[INJECT]` tags with specified payload (supports url, data, headers, cookies)
- Multiple HTTP methods will result in separate request for each
- Request body will not be automatically encoded or formated based on content type
- A wordlist can be supplied as input through `-W` or `--wordlist` argument
- Strings of interest can be extracted through regex pattern through `-E` or `--extract` tag
- Response details or status codes can be filtered by supplying CRC or code in `-B` or `--ban` arguments (supports multiple values)
- Request headers can be set by through  `-H` or `--header` tags (supports multiple values)
- Associated cookies can be configured by supplying  `-C` or `--cookie` argument (supports multiple values)
- Request data can be set by through `-D` or `--data` tag (requires manual content-type header)
- Fuzzing speed can be controlled by `-S` or `--speed` argument which defines amount of concurent threads
- Request HTTP methods used in fuzzing can be sent by supplying  `-M` or `--method` tags (supports multiple values)
- Keyword used for payload replacement can be modified with `-T` or `--TAG` argument
- Redirect handling can be controlled through `-R` or `--redirect` tag
- HTTP request timeout can be set bu supplying `-O` or `--timeout` argument
- Verbose output, including full response body can be enabled by `-V` or `--verbose` tag 
- Proxy for outgoing requests can be configured through `-X` or `--proxy` argument

## Demo

![demo](yafuzz.gif)

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
