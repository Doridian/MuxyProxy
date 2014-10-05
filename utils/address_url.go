package utils

import (
	"regexp"
	"strings"
)

var addressURLRegex = regexp.MustCompile("^([^\\[:]+)(\\[[^\\]]+\\])?://(.+)$")

type FullAddress struct {
	Host string
	Protocol string
	Options map[string]bool
	Tls bool
}

func (f *FullAddress) IsTCP() bool {
	return f.Protocol == "tcp" || f.Protocol == "tcp4" || f.Protocol == "tcp6"
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
	
	ret.Options = make(map[string]bool)
	if len(matches[2]) > 0 {
		for _, option := range strings.Split(matches[2][1:len(matches[2])-1], ";") {
			ret.Options[option] = true
		}
	}
	
	ret.Host = matches[3]
	
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