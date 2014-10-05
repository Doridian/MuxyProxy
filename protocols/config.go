package protocols

import (
	"regexp"
	"os"
	"encoding/json"
)

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

func Load(fileName string) (*ProxyProtocolConfig, error) {
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