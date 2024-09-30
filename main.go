package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"text/tabwriter"
	"time"
)

/*
IPScope is a CLI tool for IP lookup and subdomain discovery.
Designed for security researchers and network administrators to resolve IP addresses for TLDs and subdomains.
Includes support for some reverse proxy and WAF detection.

written in Pure Go by cyclone

GNU General Public License v2.0
https://github.com/cyclone-github/ipscope/blob/main/LICENSE

Version History:

0.1.0-2023-12-15
	Initial version
0.2.1-2024-09-30
	Refactored code
	Refined flags
	Added domain lookup from crt.sh
	Added proxy / WAF checks
	Added CloudFlare IP lookup
	Added built-in subdomain lists
*/

const cloudflareIPv4URL = "https://www.cloudflare.com/ips-v4/"

type IPInfo struct {
	Org string `json:"org"`
}

func main() {
	// define flags
	urlFlag := flag.String("url", "", "URL to process")
	subFlag := flag.String("sub", "", "File containing subdomains")
	dnsFlag := flag.String("dns", "1.1.1.1", "Custom DNS server (ex: 1.1.1.1)")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Version info")
	helpFlag := flag.Bool("help", false, "Display help")
	flag.Parse()

	if *cycloneFlag {
		codedBy := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		codedByDecoded, _ := base64.StdEncoding.DecodeString(codedBy)
		fmt.Fprintln(os.Stderr, string(codedByDecoded))
		os.Exit(0)
	}

	if *helpFlag {
		helpFunc()
		os.Exit(0)
	}

	if *versionFlag {
		versionFunc()
		os.Exit(0)
	}

	if *urlFlag == "" {
		helpFunc()
		os.Exit(1)
	}

	domain := *urlFlag

	// DNS resolver
	customResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout: time.Second * 10,
			}
			return dialer.DialContext(ctx, "udp", *dnsFlag+":53")
		},
	}

	// tabwriter
	writer := new(tabwriter.Writer)
	writer.Init(os.Stdout, 0, 8, 2, ' ', tabwriter.AlignRight)
	defer writer.Flush()

	printCyclone()

	fmt.Fprintf(writer, "Processing URL: %s using DNS: %s\n\n", domain, *dnsFlag)
	writer.Flush()

	// load Cloudflare IP ranges
	loadCloudflareIPs()

	// create a map to track processed subdomains
	processedSubdomains := make(map[string]bool)

	// get subdomains from crt.sh
	retries := 5
	var crtSubdomains []string
	var err error

	for i := 0; i < retries; i++ {
		writer.Flush()
		crtSubdomains, err = getSubdomainsFromCRT(domain)
		if err == nil {
			break
		}
		writer.Flush()
		time.Sleep(5 * time.Second)
	}

	if err != nil {
		writer.Flush()
	} else {
		// process crtSubdomains first
		for _, fullDomain := range crtSubdomains {
			processedSubdomains[fullDomain] = true

			label := "SUB"
			if fullDomain == domain || fullDomain == "www."+domain {
				label = "TLD"
			}

			if ips, err := customResolver.LookupIP(context.Background(), "ip4", fullDomain); err == nil {
				printOutput(writer, label, fullDomain, ips)
				writer.Flush()
			}
		}
	}

	// check TLD IP using custom resolver
	if !processedSubdomains[domain] {
		tldIPs, err := customResolver.LookupIP(context.Background(), "ip4", domain)
		if err != nil {
			fmt.Fprintf(writer, "Error getting IP for TLD (%s): %v\n", domain, err)
		} else {
			printOutput(writer, "TLD", domain, tldIPs)
			writer.Flush()
			processedSubdomains[domain] = true
		}
	}

	if *subFlag != "" {
		file, err := os.Open(*subFlag)
		if err != nil {
			fmt.Fprintf(writer, "Error opening subdomains file (%s): %v\n", *subFlag, err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			subdomain := scanner.Text()
			fullDomain := fmt.Sprintf("%s.%s", subdomain, domain)
			if processedSubdomains[fullDomain] {
				continue
			}
			processedSubdomains[fullDomain] = true
			if ips, err := customResolver.LookupIP(context.Background(), "ip4", fullDomain); err == nil {
				printOutput(writer, "SUB", fullDomain, ips)
				writer.Flush()
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(writer, "Error reading subdomains file (%s): %v\n", *subFlag, err)
		}
	} else {
		for _, subdomain := range defaultSubdomains() {
			fullDomain := fmt.Sprintf("%s.%s", subdomain, domain)
			if processedSubdomains[fullDomain] {
				continue
			}
			processedSubdomains[fullDomain] = true
			if ips, err := customResolver.LookupIP(context.Background(), "ip4", fullDomain); err == nil {
				printOutput(writer, "SUB", fullDomain, ips)
				writer.Flush()
			}
		}
	}
}
