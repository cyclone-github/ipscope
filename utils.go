package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

const maxBackoff = 60 * time.Second
const initialBackoff = 10 * time.Second

var cloudflareIPNets []*net.IPNet

func init() {
	// static Cloudflare IP ranges
	staticIPs := []string{
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
	}
	for _, cidr := range staticIPs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Printf("Failed to parse Cloudflare IP range %s: %v\n", cidr, err)
			continue
		}
		cloudflareIPNets = append(cloudflareIPNets, ipnet)
	}
}

// print info
func printOutput(writer *tabwriter.Writer, label, domain string, ips []net.IP) {
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			if !isValidPublicIPv4(ipv4) {
				continue
			}

			org, err := getIPInfo(ipv4.String())
			if err != nil {
				fmt.Fprintf(writer, "Error fetching organization info: %v\n", err)
			} else {
				isReverseProxy := checkCloudFlare(ipv4.String()) || checkKnownWAF(org)
				if isReverseProxy {
					fmt.Fprintf(writer, "%-3s\t%-24s\t%-20s\t%-24s (Reverse Proxy or WAF Detected)\n", label, domain, ipv4, org)
				} else {
					fmt.Fprintf(writer, "%-3s\t%-24s\t%-20s\t%-24s\n", label, domain, ipv4, org)
				}
			}
		}
	}
}

// check if known WAF
func checkKnownWAF(org string) bool {
	org = strings.ToLower(org)
	return strings.Contains(org, "cloudflare") || // Cloudflare
		strings.Contains(org, "akamai") || // Akamai
		strings.Contains(org, "amazon") || // Amazon AWS
		strings.Contains(org, "fastly") || // Fastly
		strings.Contains(org, "imperva") || // Imperva
		strings.Contains(org, "incapsula") || // Incapsula
		strings.Contains(org, "sucuri") || // Sucuri
		strings.Contains(org, "stackpath") || // StackPath
		strings.Contains(org, "f5") || // F5 Networks
		strings.Contains(org, "google") || // Google
		strings.Contains(org, "microsoft") || // Microsoft
		strings.Contains(org, "barracuda") || // Barracuda
		strings.Contains(org, "citrix") || // Citrix
		strings.Contains(org, "cloudfront") || // CloudFront
		strings.Contains(org, "verizon") || // Verizon
		strings.Contains(org, "fortinet") || // Fortinet
		strings.Contains(org, "edgecast") || // Edgecast
		strings.Contains(org, "dyn") || // Dyn
		strings.Contains(org, "radware") || // Radware
		strings.Contains(org, "azure") || // Azure
		strings.Contains(org, "arvancloud") || // ArvanCloud
		strings.Contains(org, "onapp") || // OnApp
		strings.Contains(org, "bitninja") || // BitNinja
		strings.Contains(org, "reblaze") || // Reblaze
		strings.Contains(org, "section.io") || // Section.io
		strings.Contains(org, "neustar") || // Neustar
		strings.Contains(org, "blazingfast") || // BlazingFast
		strings.Contains(org, "quantil") || // QUANTIL
		strings.Contains(org, "cdnsun") // CDNSun
}

// get org info from IP
func getIPInfo(ip string) (string, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)
	backoffTime := initialBackoff

	for {
		resp, err := http.Get(url)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			retryAfter := resp.Header.Get("Retry-After")
			waitTime := backoffTime
			if retryAfter != "" {
				if seconds, err := strconv.Atoi(retryAfter); err == nil {
					waitTime = time.Duration(seconds) * time.Second
					fmt.Printf("Rate-limited: Retrying after %s...\n", waitTime)
				}
			}

			time.Sleep(waitTime)
			if waitTime < maxBackoff {
				backoffTime += time.Second
			} else {
				backoffTime = maxBackoff
			}
			continue
		}

		var ipInfo IPInfo
		if err := json.NewDecoder(resp.Body).Decode(&ipInfo); err != nil {
			return "", err
		}

		return ipInfo.Org, nil
	}
}

// check if IP belongs to Cloudflare
func checkCloudFlare(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, ipnet := range cloudflareIPNets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func loadCloudflareIPs() {
	resp, err := http.Get(cloudflareIPv4URL)
	if err != nil {
		fmt.Println("Failed to download Cloudflare IPs, using static list.")
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read Cloudflare IPs, using static list.")
		return
	}

	ips := strings.Split(string(body), "\n")
	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(ipStr)
		if err != nil {
			fmt.Printf("Failed to parse Cloudflare IP range %s: %v\n", ipStr, err)
			continue
		}
		cloudflareIPNets = append(cloudflareIPNets, ipnet)
	}
}

// validate if IP is a public IPv4 address
func isValidPublicIPv4(ip net.IP) bool {
	privateRanges := []string{
		"0.0.0.0/8",      // Reserved
		"10.0.0.0/8",     // Private Network
		"172.16.0.0/12",  // Private Network
		"192.168.0.0/16", // Private Network
		"127.0.0.0/8",    // Loopback
		"169.254.0.0/16", // Link-local
	}

	for _, cidr := range privateRanges {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return false
		}
	}

	return ip.To4() != nil
}

// version info
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's IPScope v0.2.1-2024-09-30\nhttps://github.com/cyclone-github/ipscope\n")
}

// cyclone
func printCyclone() {
	cyclone := `
                   _                   
  ____ _   _  ____| | ___  ____  _____ 
 / ___) | | |/ ___) |/ _ \|  _ \| ___ |
( (___| |_| ( (___| | |_| | | | | ____|
 \____)\__  |\____)\_)___/|_| |_|_____)
      (____/                           
`
	fmt.Println(cyclone)
	time.Sleep(250 * time.Millisecond)
}

// help info
func helpFunc() {
	versionFunc()
	str := `Example Usage:

./ipscope.bin -url example.com
./ipscope.bin -url example.com -sub subdomains.txt -dns 8.8.8.8

Supported flags:

-url example.com (required)
-sub subdomain.txt (optional, defaults to built-in list)
-dns 8.8.8.8 (optional, defaults to 1.1.1.1)

-help (usage instructions)
-version (version info)`
	fmt.Fprintln(os.Stderr, str)
}
