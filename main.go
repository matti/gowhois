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
	Description  string
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
			result.Description = value
		case "address":
			addresses = append(addresses, value)
		}
	}

	if result.Organization == "" && len(addresses) > 0 {
		result.Organization = addresses[0]
	}
	return result
}
