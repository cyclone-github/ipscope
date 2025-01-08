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
			fmt.Fprintf(os.Stderr, "Failed to parse Cloudflare IP range %s: %v\n", cidr, err)
			continue
		}
		cloudflareIPNets = append(cloudflareIPNets, ipnet)
	}
}

// print info
func printOutput(writer *tabwriter.Writer, label, domain string, ips []net.IP, jsonOutput bool) {
	type JSONOutput struct {
		Label   string `json:"label"`
		Domain  string `json:"domain"`
		IP      string `json:"ip"`
		Asn     string `json:"asn"`
		City    string `json:"city"`
		Region  string `json:"region"`
		Country string `json:"country"`
		Proxy   bool   `json:"proxy"`
	}

	for _, ip := range ips {
		ipv4 := ip.To4()
		if ipv4 == nil || !isValidPublicIPv4(ipv4) {
			continue
		}

		ipInfo, err := getIPInfo(ipv4.String())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching IP info for %s: %v\n", ipv4.String(), err)
			continue
		}

		isReverseProxy := checkCloudFlare(ipv4.String()) || checkKnownWAF(ipInfo.Org)

		if jsonOutput {
			// JSON output format
			output := JSONOutput{
				Label:   label,
				Domain:  domain,
				IP:      ipv4.String(),
				Asn:     ipInfo.Org,
				City:    ipInfo.City,
				Region:  ipInfo.Region,
				Country: ipInfo.Country,
				Proxy:   isReverseProxy,
			}
			jsonData, _ := json.Marshal(output)
			fmt.Println(string(jsonData))
		} else {
			// tabwriter "pretty" output
			if isReverseProxy {
				fmt.Fprintf(writer, "%-3s\t%-25s\t%-16s\t%-32s\t %s, %s, %s (Reverse Proxy or WAF Detected)\n", label, domain, ipv4, ipInfo.Org, ipInfo.City, ipInfo.Region, ipInfo.Country)
			} else {
				fmt.Fprintf(writer, "%-3s\t%-25s\t%-16s\t%-32s\t %s, %s, %s\n", label, domain, ipv4, ipInfo.Org, ipInfo.City, ipInfo.Region, ipInfo.Country)
			}
		}
	}
}

// check if known WAF
func checkKnownWAF(org string) bool {
	org = strings.ToLower(org)
	return strings.Contains(org, "cloudflare") || // Cloudflare
		strings.Contains(org, "360.cn") || // Qihoo 360
		strings.Contains(org, "akamai") || // Akamai
		strings.Contains(org, "aliyun") || // Alibaba Cloud
		strings.Contains(org, "amazon") || // Amazon AWS
		strings.Contains(org, "arvancloud") || // ArvanCloud
		strings.Contains(org, "aws waf") || // AWS WAF
		strings.Contains(org, "azure") || // Azure
		strings.Contains(org, "baidu") || // Baidu Cloud
		strings.Contains(org, "barracuda") || // Barracuda
		strings.Contains(org, "bitninja") || // BitNinja
		strings.Contains(org, "blazingfast") || // BlazingFast
		strings.Contains(org, "cdnsun") || // CDNSun
		strings.Contains(org, "citrix") || // Citrix
		strings.Contains(org, "cloudfront") || // CloudFront
		strings.Contains(org, "digitalocean") || // DigitalOcean
		strings.Contains(org, "dyn") || // Dyn
		strings.Contains(org, "edgecast") || // Edgecast
		strings.Contains(org, "f5") || // F5 Networks
		strings.Contains(org, "fastly") || // Fastly
		strings.Contains(org, "fortinet") || // Fortinet
		strings.Contains(org, "gcore") || // Gcore
		strings.Contains(org, "google") || // Google
		strings.Contains(org, "imperva") || // Imperva
		strings.Contains(org, "incapsula") || // Imperva Incapsula
		strings.Contains(org, "incapsula") || // Incapsula
		strings.Contains(org, "kingsoft") || // Kingsoft Cloud
		strings.Contains(org, "limelight") || // Limelight Networks
		strings.Contains(org, "microsoft") || // Microsoft
		strings.Contains(org, "neustar") || // Neustar
		strings.Contains(org, "onapp") || // OnApp
		strings.Contains(org, "quantil") || // QUANTIL
		strings.Contains(org, "radware") || // Radware
		strings.Contains(org, "reblaze") || // Reblaze
		strings.Contains(org, "section.io") || // Section.io
		strings.Contains(org, "shield") || // Cloudflare Spectrum/Shield
		strings.Contains(org, "stackpath") || // StackPath
		strings.Contains(org, "stackrox") || // StackRox
		strings.Contains(org, "sucuri") || // Sucuri
		strings.Contains(org, "tencent") || // Tencent Cloud
		strings.Contains(org, "verizon") || // Verizon
		strings.Contains(org, "vultr") // Vultr
}

// get org info from IP
func getIPInfo(ip string) (*IPInfo, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)
	backoffTime := initialBackoff

	for {
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			retryAfter := resp.Header.Get("Retry-After")
			waitTime := backoffTime
			if retryAfter != "" {
				if seconds, err := strconv.Atoi(retryAfter); err == nil {
					waitTime = time.Duration(seconds) * time.Second
					fmt.Fprintf(os.Stderr, "Rate-limited: Retrying after %s...\n", waitTime)
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
			return nil, err
		}

		return &ipInfo, nil
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
		fmt.Fprintln(os.Stderr, "Failed to download Cloudflare IPs, using static list.")
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read Cloudflare IPs, using static list.")
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
			fmt.Fprintf(os.Stderr, "Failed to parse Cloudflare IP range %s: %v\n", ipStr, err)
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
	fmt.Fprint(os.Stderr, "Cyclone's IPScope v0.2.4; 2025-01-08\nhttps://github.com/cyclone-github/ipscope\n\n")
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
	fmt.Fprintln(os.Stderr, cyclone)
	versionFunc()
	time.Sleep(250 * time.Millisecond)
}

// help info
func helpFunc() {
	versionFunc()
	str := `Example Usage:

./ipscope.bin -url example.com
./ipscope.bin -url example.com -sub subdomains.txt -dns 8.8.8.8 -json -o output.txt

Supported flags:

-url		(url to scan)
-sub		(defaults to built-in list)
-dns		(defaults to 1.1.1.1)
-json		(outputs stdout to json)
-o		(redirects stdout to file)
-help		(usage instructions)
-version	(version info)`
	fmt.Fprintln(os.Stderr, str)
}
