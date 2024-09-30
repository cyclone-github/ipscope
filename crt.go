package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type CRTSHEntry struct {
	NameValue string `json:"name_value"`
}

func getSubdomainsFromCRT(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get data from crt.sh, status code %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []CRTSHEntry
	if err := json.Unmarshal(bodyBytes, &entries); err != nil {
		return nil, err
	}

	subdomainsSet := make(map[string]struct{})
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if strings.HasSuffix(name, domain) {
				subdomainsSet[name] = struct{}{}
			}
		}
	}

	var subdomains []string
	for subdomain := range subdomainsSet {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}
