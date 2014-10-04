package main

import (
	"regexp"
	"os"
	"encoding/json"
	"log"
)

type ProxyProtocolConfig struct {
	LINE_PROTOCOLS_REGEXP map[string]*regexp.Regexp
	LINE_PROTOCOLS_LITERAL map[string][]int
	RAW_PROTOCOLS_REGEXP map[string]*regexp.Regexp
	RAW_PROTOCOLS_LITERAL map[string][]int
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
	Value interface{}
}

func LoadProtocols(fileName string) *ProxyProtocolConfig {
	c := new(ProxyProtocolConfig)
	c.LINE_PROTOCOLS_REGEXP = make(map[string]*regexp.Regexp)
	c.LINE_PROTOCOLS_LITERAL = make(map[string][]int)
	c.RAW_PROTOCOLS_REGEXP = make(map[string]*regexp.Regexp)
	c.RAW_PROTOCOLS_LITERAL = make(map[string][]int)

	protocolsConfig := make(map[string]protocolConfigJSON)

	fileReader, err := os.Open(fileName)
	if err != nil {
		log.Panicf("Load CProtocols: open err: %v", err)
	}	
	jsonReader := json.NewDecoder(fileReader)
	err = jsonReader.Decode(&protocolsConfig)
	fileReader.Close()
	if err != nil {
		log.Panicf("Load CProtocols: json err: %v", err)
	}
	
	for name, protocolConfig := range protocolsConfig {
		value := protocolConfig.Value
		switch protocolConfig.Type {
			case "line_regex": {
				c.LINE_PROTOCOLS_REGEXP[name] = regexp.MustCompile(protocolConfig.Value.(string))
			}
			case "line_bytes": {
				c.LINE_PROTOCOLS_LITERAL[name] = literalMatchFromArray(value.([]interface{}))
			}
			case "line_string": {
				c.LINE_PROTOCOLS_LITERAL[name] = literalMatchFromString(protocolConfig.Value.(string))
			}
			
			case "raw_regex": {
				c.RAW_PROTOCOLS_REGEXP[name] = regexp.MustCompile(protocolConfig.Value.(string))
			}
			case "raw_bytes": {
				c.RAW_PROTOCOLS_LITERAL[name] = literalMatchFromArray(value.([]interface{}))
			}
			case "raw_string": {
				c.RAW_PROTOCOLS_LITERAL[name] = literalMatchFromString(protocolConfig.Value.(string))
			}
		}
	}
	
	log.Println("Load CProtocols: OK")
	
	return c
}