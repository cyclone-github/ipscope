[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=ipscope&theme=gruvbox)](https://github.com/cyclone-github/)
# Cyclone's IPScope

A CLI tool written in Pure Go for IP lookup and subdomain discovery. Designed for security researchers and network administrators to resolve IP addresses for TLDs and subdomains. Includes support for some reverse proxy and WAF detection.

### Usage Instructions:
- Example Usage:
  - `./ipscope.bin -url example.com`
  - `./ipscope.bin -url example.com -sub subdomains.txt -dns 8.8.8.8`

- Supported flags:
  - `-url example.com (required)`
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
