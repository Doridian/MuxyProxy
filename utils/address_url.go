package utils

import (
	"regexp"
	"strings"
)

var addressURLRegex = regexp.MustCompile("^([^:]+)://(.+)$")

type FullAddress struct {
	Host string
	Protocol string
	Tls bool
}

func DecodeAddressURL(url string) FullAddress {
	var ret FullAddress
	ret.Host = url
	ret.Protocol = "tcp"
	ret.Tls = false

	matches := addressURLRegex.FindStringSubmatch(url)
	if matches == nil {
		return ret
	}
	
	ret.Host = matches[2]
	
	protocols := strings.Split(matches[1], "+")
	for _, proto := range protocols {
		if proto == "ssl" || proto == "tls" {
			ret.Tls = true
		} else {
			ret.Protocol = proto
		}
	}
	
	return ret
}