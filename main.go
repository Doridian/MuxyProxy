package main

import (
	"log"
	"net"
	"time"
	"regexp"
	"io"
	"os"
	"encoding/json"
)

var LINE_PROTOCOLS_REGEXP = make(map[string]*regexp.Regexp)
var LINE_PROTOCOLS_LITERAL = make(map[string][]int)
var RAW_PROTOCOLS_REGEXP = make(map[string]*regexp.Regexp)
var RAW_PROTOCOLS_LITERAL = make(map[string][]int)

var _DEBUG = true

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

type protocolConfig struct {
	Type string
	Value interface{}
}

func loadProtocolsConfig() {
	protocolsConfig := make(map[string]protocolConfig)

	fileReader, err := os.Open("protocols.json")
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
				LINE_PROTOCOLS_REGEXP[name] = regexp.MustCompile(protocolConfig.Value.(string))
			}
			case "line_bytes": {
				LINE_PROTOCOLS_LITERAL[name] = literalMatchFromArray(value.([]interface{}))
			}
			case "line_string": {
				LINE_PROTOCOLS_LITERAL[name] = literalMatchFromString(protocolConfig.Value.(string))
			}
			
			case "raw_regex": {
				RAW_PROTOCOLS_REGEXP[name] = regexp.MustCompile(protocolConfig.Value.(string))
			}
			case "raw_bytes": {
				RAW_PROTOCOLS_LITERAL[name] = literalMatchFromArray(value.([]interface{}))
			}
			case "raw_string": {
				RAW_PROTOCOLS_LITERAL[name] = literalMatchFromString(protocolConfig.Value.(string))
			}
		}
	}
	
	log.Println("Load CProtocols: OK")
}

type ProxyListener struct {
	ProtocolHosts map[string]string
	FallbackProtocol string
	ListenerAddress string
	ProtocolDiscoveryTimeout float64
	protocolDiscoveryTimeoutReal time.Duration
}

func (p *ProxyListener) Start() {
	p.protocolDiscoveryTimeoutReal = time.Duration(p.ProtocolDiscoveryTimeout) * time.Second

	listenerAddr, err := net.ResolveTCPAddr("tcp", p.ListenerAddress)
	if err != nil {
		log.Printf("Could not resolve listener: %v", err)
	}
	listener, err := net.ListenTCP("tcp", listenerAddr)
	if err != nil {
		log.Printf("Could not listen: %v", err)
	}
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go p.handleConnection(conn)
	}
}

func main() {
	loadProtocolsConfig()
	loadListenerConfig()
	log.Println("GO")
	for {
		time.Sleep(10 * time.Minute)
	}
}

func loadListenerConfig() {
	var listenersConfig []ProxyListener

	fileReader, err := os.Open("listeners.json")
	if err != nil {
		log.Panicf("Load CListeners: open err: %v", err)
	}	
	jsonReader := json.NewDecoder(fileReader)
	err = jsonReader.Decode(&listenersConfig)
	fileReader.Close()
	if err != nil {
		log.Panicf("Load CListeners: json err: %v", err)
	}
	
	for _,listener := range listenersConfig {
		go listener.Start()
	}
	
	log.Println("Load CListeners: OK")
}

func (p *ProxyListener) handleConnection(client *net.TCPConn) {
	protocolPtr, headBytes := p.connectionDiscoverProtocol(client)
	
	var protocol string
	if protocolPtr == nil {
		protocol = p.FallbackProtocol
	} else {
		protocol = *protocolPtr
	}
	
	if _DEBUG {
		log.Printf("Found protocol: %v", protocol)
	}
	
	var addrStr string
	var ok bool
	if addrStr, ok = p.ProtocolHosts[protocol]; !ok {
		log.Printf("No handler for protocol %v defined. Disconnecting.", protocol)
		client.Close()
		return
	}
	
	
	addr, err := net.ResolveTCPAddr("tcp", addrStr)
	if err != nil {
		log.Printf("Protocol error (%v): %v", addrStr, err)
		client.Close()
		return
	}
	
	server, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		log.Printf("Error establishing backend connection for protocol %s: %v", protocol, err)
		client.Close()
		return
	}
	
	server.SetNoDelay(true)
	client.SetNoDelay(true)
	
	server.Write(headBytes)
	
	go io.Copy(server, client)
	go io.Copy(client, server)
}

func whichProtocolIs(data []byte) *string {
	if len(data)  < 1 {
		return nil
	}

	hasNewline := false
	firstLine := make([]byte, 0)
	for i,b := range data {
		if b == '\n' {
			hasNewline = true
			if i < 1 {
				//We keep firstLine empty
			} else if data[i - 1] == '\r' {
				if i >= 2 {
					firstLine = data[0 : i - 2]
				}
			} else {
				firstLine = data[0 : i - 1]
			}
			break
		}
	}
	
	if hasNewline {
		for protocol,literal := range LINE_PROTOCOLS_LITERAL {
			if len(firstLine) < len(literal) {
				continue
			}
			literalIsValid := true
			for i, b := range literal {
				if b >= 0 && firstLine[i] != byte(b) {
					literalIsValid = false
					break
				}
			}
			if literalIsValid {
				return &protocol
			}
		}
		for protocol,regexp := range LINE_PROTOCOLS_REGEXP {
			if regexp.Match(firstLine) {
				return &protocol
			}
		}
	}
	
	for protocol,literal := range RAW_PROTOCOLS_LITERAL {
		if len(data) < len(literal) {
			continue
		}
		literalIsValid := true
		for i, b := range literal {
			if b >= 0 && data[i] != byte(b) {
				literalIsValid = false
				break
			}
		}
		if literalIsValid {
			return &protocol
		}
	}
	for protocol,regexp := range RAW_PROTOCOLS_REGEXP {
		if regexp.Match(data) {
			return &protocol
		}
	}
	
	return nil
}

func (p *ProxyListener) connectionDiscoverProtocol(conn *net.TCPConn) (*string, []byte) {
	conn.SetNoDelay(true)
	defer conn.SetNoDelay(false)
	defer conn.SetDeadline(time.Unix(0, 0))
	
	buff := make([]byte, 128)
	pos := 0
	var foundProtocol *string
	for {
		conn.SetDeadline(time.Now().Add(p.protocolDiscoveryTimeoutReal))
		readLen, err := conn.Read(buff[pos:])
		if err != nil || readLen <= 0 {
			break
		}
		pos += readLen
		foundProtocol = whichProtocolIs(buff[0:pos])
		if foundProtocol != nil {
			return foundProtocol, buff[0:pos]
		}
	}
	
	foundProtocol = whichProtocolIs(buff[0:pos])
	
	if foundProtocol == nil {
		if _DEBUG {
			log.Printf("UN P B: %x %x %x %x %x %x %x", buff[0], buff[1], buff[2], buff[3], buff[4], buff[5], buff[6])
			log.Printf("UN P S: %s", buff[0:pos])
		}
		return nil, buff[0:pos]
	}

	return foundProtocol, buff[0:pos]
}