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
- HTTP request timeout can be set by supplying `-O` or `--timeout` argument
- Verbose output, including full response body can be enabled by `-V` or `--verbose` tag 
- Proxy for outgoing requests can be configured through `-X` or `--proxy` argument
- Encoding scheme can be set by supplying `-N` or `--encode` tag (supports url, urlall, double and unicode values)
- Replacing pattern for the resulting payload con be configured by `-L` or `--replace` argument (expects two values, src and dest)

## Demo

![demo](yafuzz.gif)

```
usage: yafuzz.py [-h] --url URL [--wordlist PATH] [--extract REGEX] [--ban 3205226431] [--header NAME:VALUE] [--cookie NAME=VALUE] [--data DATA] [--encode ENCODE] [--replace SRC DST] [--speed THREADS] [--method POST] [--tag [INJECT]]
                 [--redirect] [--timeout SECONDS] [--verbose] [--proxy http://127.0.0.1:8080]

Yet another HTTP fuzzer

optional arguments:
  -h, --help            show this help message and exit
  --url URL, -U URL     Target HTTP URL address
  --wordlist PATH, -W PATH
                        Wordlist file path
  --extract REGEX, -E REGEX
                        RegEx pattern to extract from response
  --ban 3205226431, -B 3205226431
                        Ban specific crc32 hash or response code from output
  --header NAME:VALUE, -H NAME:VALUE
                        HTTP Headers
  --cookie NAME=VALUE, -C NAME=VALUE
                        HTTP Cookies
  --data DATA, -D DATA  HTTP request body
  --encode ENCODE, -N ENCODE
                        Encode payload, url, urlall, double or unicode
  --replace SRC DST, -L SRC DST
                        Replace pattern in payloads
  --speed THREADS, -S THREADS
                        Number of threads
  --method POST, -M POST
                        HTTP method to use
  --tag [INJECT], -T [INJECT]
                        Tag to search for and replace
  --redirect, -R        Accept HTTP redirects
  --timeout SECONDS, -O SECONDS
                        Timeout of the HTTP request
  --verbose, -V         Enable verbose output
  --proxy http://127.0.0.1:8080, -X http://127.0.0.1:8080
                        Enable HTTP proxy

```
