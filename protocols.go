package main

import (
	"regexp"
	"os"
	"encoding/json"
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

type protocolMatcherRegexp struct {
	protocolMatcherBase
	regexp *regexp.Regexp
}

func (p *protocolMatcherRegexp) Matches(data []byte) bool {
	return p.regexp.Match(data)
}

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

type ProxyProtocolConfig struct {
	Matchers []ProtocolMatcher
}

func literalMatchFromString(str string) []int {
	ret := make([]int, len(str))
	for i,c := range str {
		ret[i] = int(c)
	}
	return ret
}

func literalMatchFromArray(array []interface{}) []int {
	valueInts := make([]int, len(array))
	for i,valueIface := range array {
		valueInts[i] = int(valueIface.(float64))
	}
	return valueInts
}

type protocolConfigJSON struct {
	Type string
	Protocol string
	Target string
	Value interface{}
}

func LoadProtocols(fileName string) (*ProxyProtocolConfig, error) {
	c := new(ProxyProtocolConfig)

	protocolsConfig := make([]protocolConfigJSON, 0)

	fileReader, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}	
	jsonReader := json.NewDecoder(fileReader)
	err = jsonReader.Decode(&protocolsConfig)
	fileReader.Close()
	if err != nil {
		return nil, err
	}
	
	c.Matchers = make([]ProtocolMatcher, len(protocolsConfig))
	
	for i, protocolConfig := range protocolsConfig {
		var matcher ProtocolMatcher
		switch protocolConfig.Type {
			case "regex": {
				_matcher := new(protocolMatcherRegexp)
				_matcher.regexp = regexp.MustCompile(protocolConfig.Value.(string))
				matcher = _matcher
			}
			case "bytes": {
				_matcher := new(protocolMatcherLiteral)
				_matcher.matchPattern = literalMatchFromArray(protocolConfig.Value.([]interface{}))
				matcher = _matcher
			}
			case "string": {
				_matcher := new(protocolMatcherLiteral)
				_matcher.matchPattern = literalMatchFromString(protocolConfig.Value.(string))
				matcher = _matcher
			}
		}
		matcher.setProtocol(protocolConfig.Protocol)
		matcher.setTarget(protocolConfig.Target)
		c.Matchers[i] = matcher
	}
	
	return c, nil
}