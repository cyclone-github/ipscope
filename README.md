[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=ipscope&theme=gruvbox)](https://github.com/cyclone-github/)
# IPScope

A CLI tool written in pure Go for IP lookup and subdomain discovery. Designed for security researchers and network administrators to resolve IP addresses for TLDs and subdomains. Includes support for some reverse proxy and WAF detection.

IPScope was written as a capable, no-fuss alternative to more complex CLI tools commonly used for subdomain discovery and active DNS resolution. IPScope features a simple CLI that only requires one command-line argument, the target URL, while maintaining a powerful backend and optional command-line arguments for further customization. Since it's written in Go, there's no need to hunt down outdated or obscure Python dependencies, and since it's written with ease of use in mind, there's no need to figure out complex command-line arguments -- **IPScope just works**.

### Usage Instructions:
Of course, don't run IPScope on domains you don't have permission to probe.

- Example Usage:
  - `./ipscope.bin -url example.org`
```
                   _                   
  ____ _   _  ____| | ___  ____  _____ 
 / ___) | | |/ ___) |/ _ \|  _ \| ___ |
( (___| |_| ( (___| | |_| | | | | ____|
 \____)\__  |\____)\_)___/|_| |_|_____)
      (____/                           

Processing URL: example.org using DNS: 1.1.1.1

  TLD  example.org               93.184.215.14       AS15133 Edgecast Inc.    (Reverse Proxy or WAF Detected)
  TLD  www.example.org           93.184.215.14       AS15133 Edgecast Inc.    (Reverse Proxy or WAF Detected)
```
  - `./ipscope.bin -url example.org -sub subdomains.txt -dns 8.8.8.8`

The `-dns` flag is useful for testing how a domain resolves with specific DNS servers, such as 1.1.1.1, 8.8.8.8, or DNS based filtering such as Cloudflare 1.1.1.3 or OpenDNS 208.67.222.222. It’s also great for testing locally hosted DNS servers like Pi-hole or pfSense.

The tool can also be used with a custom subdomain list via the `-sub` flag to verify if known subdomains are resolving correctly through services like Cloudflare, or to check if they are leaking their host IP.

If neither the `-dns` nor `-sub` flags are given, the tool defaults to 1.1.1.1 and a built-in list of the top 10k common subdomains.

- Supported flags:
  - `-url example.org (required)`
  - `-sub subdomain.txt (optional, defaults to built-in list)`
  - `-dns 8.8.8.8 (optional, defaults to 1.1.1.1)`
  - `-help (usage instructions)`
  - `-version (version info)`

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/ipscope.git`
  - `cd ipscope`
  - `go mod init ipscope`
  - `go mod tidy`
  - `go build -ldflags="-s -w" .`
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
### Change Log:
- https://github.com/cyclone-github/ipscope/blob/main/CHANGELOG.md

### Antivirus False Positives:
- Several antivirus programs on VirusTotal incorrectly detect compiled Go binaries as a false positive. This issue primarily affects the Windows executable binary, but is not limited to it. If this concerns you, I recommend carefully reviewing the source code, then proceed to compile the binary yourself.
- Uploading your compiled binaries to https://virustotal.com and leaving an up-vote or a comment would be helpful as well.
