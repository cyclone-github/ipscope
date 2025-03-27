[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=ipscope&theme=gruvbox)](https://github.com/cyclone-github/ipscope/)

[![Go Report Card](https://goreportcard.com/badge/github.com/cyclone-github/ipscope)](https://goreportcard.com/report/github.com/cyclone-github/ipscope)
[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/ipscope.svg)](https://github.com/cyclone-github/ipscope/issues)
[![License](https://img.shields.io/github/license/cyclone-github/ipscope.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/ipscope.svg)](https://github.com/cyclone-github/ipscope/releases)
<!-- [![Go Reference](https://pkg.go.dev/badge/github.com/cyclone-github/ipscope.svg)](https://pkg.go.dev/github.com/cyclone-github/ipscope) -->

# IPScope

A CLI tool written in pure Go for subdomain discovery and IP lookup. Designed for security researchers and network administrators to resolve IP addresses for TLDs and subdomains. Includes support for some reverse proxy and WAF detection.

IPScope was written as a capable, no-fuss alternative to more complex CLI tools commonly used for subdomain discovery and active DNS resolution. IPScope features a simple CLI that only requires one command-line argument, the target URL, while maintaining a powerful backend and optional command-line arguments for further customization. Since it's written in Go, there's no need to hunt down outdated or obscure Python / Ruby / Perl dependencies (we've all been there), and since it's written with ease of use in mind, there's no need to figure out complex command-line arguments -- **IPScope just works**.

### Usage Instructions:
Of course, don't run IPScope on domains you don't have permission to probe.

- `./ipscope.bin -url example.org`
```
                   _                   
  ____ _   _  ____| | ___  ____  _____ 
 / ___) | | |/ ___) |/ _ \|  _ \| ___ |
( (___| |_| ( (___| | |_| | | | | ____|
 \____)\__  |\____)\_)___/|_| |_|_____)
      (____/                           

Cyclone's IPScope v0.2.4; 2025-01-08
https://github.com/cyclone-github/ipscope

Processing URL: example.org using DNS: 1.1.1.1

  TLD  example.org                93.184.215.14     AS15133 Edgecast Inc.            Dźwirzyno, West Pomerania, PL (Reverse Proxy or WAF Detected)
  TLD  www.example.org            93.184.215.14     AS15133 Edgecast Inc.            Dźwirzyno, West Pomerania, PL (Reverse Proxy or WAF Detected)
```
  - `./ipscope.bin -url example.org -sub subdomains.txt -dns 8.8.8.8 -json`
```
                   _                   
  ____ _   _  ____| | ___  ____  _____ 
 / ___) | | |/ ___) |/ _ \|  _ \| ___ |
( (___| |_| ( (___| | |_| | | | | ____|
 \____)\__  |\____)\_)___/|_| |_|_____)
      (____/                           

Cyclone's IPScope v0.2.4; 2025-01-08
https://github.com/cyclone-github/ipscope

Processing URL: example.org using DNS: 8.8.8.8

{"label":"TLD","domain":"www.example.org","ip":"93.184.215.14","asn":"AS15133 Edgecast Inc.","city":"Dźwirzyno","region":"West Pomerania","country":"PL","proxy":true}
{"label":"TLD","domain":"example.org","ip":"93.184.215.14","asn":"AS15133 Edgecast Inc.","city":"Dźwirzyno","region":"West Pomerania","country":"PL","proxy":true}
```
  - `./ipscope.bin -url example.org -sub subdomains.txt -dns 8.8.8.8 -json -o output.txt`
```
                   _                   
  ____ _   _  ____| | ___  ____  _____ 
 / ___) | | |/ ___) |/ _ \|  _ \| ___ |
( (___| |_| ( (___| | |_| | | | | ____|
 \____)\__  |\____)\_)___/|_| |_|_____)
      (____/                           

Cyclone's IPScope v0.2.4; 2025-01-08
https://github.com/cyclone-github/ipscope

Processing URL: example.org using DNS: 8.8.8.8

Output redirected to file: output.txt
```
### Supported flags:
  - `-url {foobar.com}        (url to scan)`
  - `-sub {subdirectory_file} (defaults to built-in list)`
  - `-dns {dns_server}           (defaults to 1.1.1.1)`
  - `-json                    (outputs stdout to json format)`
  - `-o {output_file}         (redirects stdout to file)`
  - `-help                    (prints usage instructions)`
  - `-version                 (prints version info)`

The `-dns` flag is useful for testing how a domain resolves with a specific DNS server, such as 1.1.1.1, 8.8.8.8, or DNS based filtering such as Cloudflare 1.1.1.3 or OpenDNS 208.67.222.222. It’s also great for testing locally hosted DNS servers like Pi-hole or pfSense.

The tool can also be used with a custom subdomain list via the `-sub` flag to verify if known subdomains are resolving correctly through services like Cloudflare, or to check if they are leaking their host IP.

The `-json` flag will format stdout to json, while the `-o` flag will redirect stdout to file.

If neither the `-dns` nor `-sub` flags are given, the tool defaults to 1.1.1.1 and a built-in list of the top 10k common subdomains.

IPScope output is:
`label` `domain` `ip` `asn` `city` `region` `country` `proxy`

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/ipscope.git`  # clone repo
  - `cd ipscope`                                               # enter project directory
  - `go mod init ipscope`                                      # initialize Go module (skips if go.mod exists)
  - `go mod tidy`                                              # download dependencies
  - `go build -ldflags="-s -w" .`                              # compile binary in current directory
  - `go install -ldflags="-s -w" .`                            # compile binary and install to $GOPATH
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
### Changelog:
- https://github.com/cyclone-github/ipscope/blob/main/CHANGELOG.md

### Antivirus False Positives:
- Several antivirus programs on VirusTotal incorrectly detect compiled Go binaries as a false positive. This issue primarily affects the Windows executable binary, but is not limited to it. If this concerns you, I recommend carefully reviewing the source code, then proceed to compile the binary yourself.
- Uploading your compiled binaries to https://virustotal.com and leaving an up-vote or a comment would be helpful as well.
