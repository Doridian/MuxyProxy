package protocols

import (
	"regexp"
)

type protocolMatcherRegexp struct {
	protocolMatcherBase
	regexp *regexp.Regexp
}

func (p *protocolMatcherRegexp) Matches(data []byte) bool {
	return p.regexp.Match(data)
}
