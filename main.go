package gowhois

import (
	"fmt"
	"strings"

	"github.com/likexian/whois"
)

type IpResult struct {
	Ip           string
	Id           string
	Organization string
	NetName      string
}

func QueryIp(ip string) *IpResult {
	result := &IpResult{
		Ip: ip,
	}

	lines, err := whois.Whois(ip)
	if err != nil {
		fmt.Println(err)
	}

	var addresses []string

	for _, line := range strings.Split(lines, "\n") {
		if strings.HasPrefix(line, "%") ||
			strings.HasPrefix(line, ";;") ||
			strings.HasPrefix(line, "#") {
			continue
		}

		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		key := parts[0]
		value := strings.TrimSpace(parts[1])

		switch key {
		case "org-name", "OrgName":
			result.Organization = value
		case "OrgId":
			result.Id = value
		case "netname", "NetName":
			result.NetName = value
		case "address":
			addresses = append(addresses, value)
		}

	}

	if result.Organization == "" {
		result.Organization = addresses[0]
	}
	return result
}
