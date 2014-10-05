package protocols

import (
	"regexp"
)

type ProtocolMatcher interface {
	Matches(data []byte) bool
	
	GetTarget() string
	GetProtocol() string
	
	setProtocol(protocol string)
	setTarget(target string)
}

type protocolMatcherBase struct {
	target string
	protocol string
}

func (p *protocolMatcherBase) GetTarget() string {
	return p.target
}

func (p *protocolMatcherBase) GetProtocol() string {
	return p.protocol
}

func (p *protocolMatcherBase) setTarget(target string) {
	p.target = target
}

func (p *protocolMatcherBase) setProtocol(protocol string) {
	p.protocol = protocol
}

//Regexp matcher
type protocolMatcherRegexp struct {
	protocolMatcherBase
	regexp *regexp.Regexp
}

func (p *protocolMatcherRegexp) Matches(data []byte) bool {
	return p.regexp.Match(data)
}

//Literal / pattern matcher
type protocolMatcherLiteral struct {
	protocolMatcherBase
	matchPattern []int
}

func (p *protocolMatcherLiteral) Matches(data []byte) bool {
	if len(data) < len(p.matchPattern) {
		return false
	}
	for i, b := range p.matchPattern {
		if b >= 0 && data[i] != byte(b) {
			return false
		}
	}
	return true
}