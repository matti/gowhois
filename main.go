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
	Role         string
	NetName      string
	Description  string
	Address      string
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
	var descrs []string

	for _, line := range strings.Split(lines, "\n") {
		if strings.HasPrefix(line, "%") ||
			strings.HasPrefix(line, ";;") ||
			line == "" {
			continue
		}
		//log.Println(line)

		// old arin changes to ripe etc
		// but 8.8.8.8 has # end
		if strings.HasPrefix(line, "#") {
			addresses = []string{}
			continue
		}

		parts := strings.SplitN(line, ":", 2)

		//descr:          APNIC Research and Development
		//                6 Cordelia St
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := strings.TrimSpace(parts[1])

		switch key {
		case "org-name", "OrgName":
			result.Organization = value
		case "organisation", "OrgId":
			result.Id = value
		case "netname", "NetName":
			result.NetName = value
		case "descr":
			descrs = append(descrs, value)
		case "role":
			result.Role = value
		case "address":
			addresses = append(addresses, value)
		}
	}

	if result.Organization == "" && result.Role != "" {
		result.Organization = result.Role
	} else if result.Organization == "" && len(descrs) > 0 {
		result.Organization = descrs[0]
	} else if result.Organization == "" && len(addresses) > 0 {
		result.Organization = addresses[0]
	}

	if len(addresses) > 0 {
		result.Address = addresses[0]
	}
	if len(descrs) > 0 {
		result.Description = descrs[0]
	}
	return result
}
