package main

import (
	"log"
	"net"
	"time"
	"regexp"
	"io"
	"os"
	"encoding/json"
	"crypto/tls"
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

type ProxyTlsConfig struct {
	Host string
	Certificate string
	PrivateKey string
}

type ProxyListener struct {
	ProtocolHosts map[string]struct {
		Host string
		Type string
	}
	FallbackProtocol string
	ListenerAddress string
	Tls *[]ProxyTlsConfig
	ProtocolDiscoveryTimeout float64
	
	protocolDiscoveryTimeoutReal time.Duration
	lineProtocolsRegexp map[string]*regexp.Regexp
	lineProtocolsLiteral map[string][]int
	rawProtocolsRegexp map[string]*regexp.Regexp
	rawProtocolsLiteral map[string][]int
}

func (p *ProxyListener) Start() {
	p.protocolDiscoveryTimeoutReal = time.Duration(p.ProtocolDiscoveryTimeout) * time.Second

	p.lineProtocolsRegexp = make(map[string]*regexp.Regexp)
	p.lineProtocolsLiteral = make(map[string][]int)
	p.rawProtocolsRegexp = make(map[string]*regexp.Regexp)
	p.rawProtocolsLiteral = make(map[string][]int)
	
	for protocol, _ := range p.ProtocolHosts {
		a, ok := LINE_PROTOCOLS_REGEXP[protocol]
		if ok {
			p.lineProtocolsRegexp[protocol] = a
		}
		b,ok := LINE_PROTOCOLS_LITERAL[protocol]
		if ok {
			p.lineProtocolsLiteral[protocol] = b
		}
		c, ok := RAW_PROTOCOLS_REGEXP[protocol]
		if ok {
			p.rawProtocolsRegexp[protocol] = c
		}
		d, ok := RAW_PROTOCOLS_LITERAL[protocol]
		if ok {
			p.rawProtocolsLiteral[protocol] = d
		}
	}

	listenerAddr, err := net.ResolveTCPAddr("tcp", p.ListenerAddress)
	if err != nil {
		log.Printf("Could not resolve listener: %v", err)
	}
	
	var listener net.Listener
	if p.Tls != nil {
		tlsConfig := new(tls.Config)
		for _, tlsHost := range *p.Tls {
			cert, err := tls.LoadX509KeyPair(tlsHost.Certificate, tlsHost.PrivateKey)
			if err != nil {
				log.Printf("Could not load keypair: %v", err)
				continue
			}
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		}
		listener, err = tls.Listen("tcp", p.ListenerAddress, tlsConfig)
	} else {
		listener, err = net.ListenTCP("tcp", listenerAddr)
	}
	if err != nil {
		log.Printf("Could not listen: %v", err)
	}
	for {
		conn, err := listener.Accept()
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

func (p *ProxyListener) handleConnection(client net.Conn) {
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
	
	protocolHost := p.ProtocolHosts[protocol]
	var server net.Conn
	var err error
	
	if protocolHost.Type == "ssl" {
		server, err = tls.Dial("tcp", protocolHost.Host, nil)
	} else {
		server, err = net.Dial(protocolHost.Type, protocolHost.Host)
	}
	
	if err != nil {
		log.Printf("Error establishing backend connection for protocol %s: %v", protocol, err)
		client.Close()
		return
	}
	
	server.Write(headBytes)
	
	go io.Copy(server, client)
	go io.Copy(client, server)
}

func (p *ProxyListener) whichProtocolIs(data []byte) *string {
	dataLen := len(data)
	if dataLen  < 1 {
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
		dataLen = len(firstLine)
		for protocol,literal := range p.lineProtocolsLiteral {
			if dataLen < len(literal) {
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
		for protocol,regexp := range p.lineProtocolsRegexp {
			if regexp.Match(firstLine) {
				return &protocol
			}
		}
	}
	
	for protocol,literal := range p.rawProtocolsLiteral {
		if dataLen < len(literal) {
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
	for protocol,regexp := range p.rawProtocolsRegexp {
		if regexp.Match(data) {
			return &protocol
		}
	}
	
	return nil
}

func (p *ProxyListener) connectionDiscoverProtocol(conn net.Conn) (*string, []byte) {
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
		foundProtocol = p.whichProtocolIs(buff[0:pos])
		if foundProtocol != nil {
			return foundProtocol, buff[0:pos]
		}
	}
	
	foundProtocol = p.whichProtocolIs(buff[0:pos])
	
	if foundProtocol == nil {
		if _DEBUG {
			log.Printf("UN P B: %x %x %x %x %x %x %x", buff[0], buff[1], buff[2], buff[3], buff[4], buff[5], buff[6])
			log.Printf("UN P S: %s", buff[0:pos])
		}
		return nil, buff[0:pos]
	}

	return foundProtocol, buff[0:pos]
}