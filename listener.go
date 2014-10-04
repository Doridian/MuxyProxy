package main

import (
	"time"
	"regexp"
	"log"
	"net"
	"io"
	"crypto/tls"
	"os"
	"encoding/json"
)

type ProxyListenerConfig struct {
	Debug bool

	Listeners []ProxyListener	
	
	config *ProxyProtocolConfig
}

type ProxyListener struct {
	Debug bool

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
	
	config *ProxyProtocolConfig
}

type ProxyTlsConfig struct {
	Host string
	Certificate string
	PrivateKey string
}

func LoadListeners(file string, config *ProxyProtocolConfig, debug bool) *ProxyListenerConfig {
	c := new(ProxyListenerConfig)
	
	fileReader, err := os.Open(file)
	if err != nil {
		log.Panicf("Load CListeners: open err: %v", err)
	}	
	jsonReader := json.NewDecoder(fileReader)
	err = jsonReader.Decode(&c.Listeners)
	fileReader.Close()
	if err != nil {
		log.Panicf("Load CListeners: json err: %v", err)
	}
	
	log.Println("Load CListeners: OK")
	
	c.config = config
	c.Debug = debug
	
	return c
}

func (c *ProxyListenerConfig) Start() {
	for _,listener := range c.Listeners {
		go listener.Start(c.config, c.Debug)
	}
}

func (p *ProxyListener) Start(config *ProxyProtocolConfig, debug bool) {
	p.config = config
	p.Debug = debug
	
	p.protocolDiscoveryTimeoutReal = time.Duration(p.ProtocolDiscoveryTimeout) * time.Second

	p.lineProtocolsRegexp = make(map[string]*regexp.Regexp)
	p.lineProtocolsLiteral = make(map[string][]int)
	p.rawProtocolsRegexp = make(map[string]*regexp.Regexp)
	p.rawProtocolsLiteral = make(map[string][]int)
	
	for protocol, _ := range p.ProtocolHosts {
		a, ok := p.config.LINE_PROTOCOLS_REGEXP[protocol]
		if ok {
			p.lineProtocolsRegexp[protocol] = a
		}
		b,ok := p.config.LINE_PROTOCOLS_LITERAL[protocol]
		if ok {
			p.lineProtocolsLiteral[protocol] = b
		}
		c, ok := p.config.RAW_PROTOCOLS_REGEXP[protocol]
		if ok {
			p.rawProtocolsRegexp[protocol] = c
		}
		d, ok := p.config.RAW_PROTOCOLS_LITERAL[protocol]
		if ok {
			p.rawProtocolsLiteral[protocol] = d
		}
	}

	listenerAddr, err := net.ResolveTCPAddr("tcp", p.ListenerAddress)
	if err != nil {
		log.Printf("Could not resolve listener: %v", err)
		return
	}
	
	listener, err := net.ListenTCP("tcp", listenerAddr)
	if err != nil {
		log.Printf("Could not listen: %v", err)
		return
	}
	
	var tlsConfig *tls.Config
	if p.Tls != nil {
		tlsConfig = new(tls.Config)
		for _, tlsHost := range *p.Tls {
			cert, err := tls.LoadX509KeyPair(tlsHost.Certificate, tlsHost.PrivateKey)
			if err != nil {
				log.Printf("Could not load keypair: %v", err)
				continue
			}
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		}
	} else {
		tlsConfig = nil
	}
	
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		
		conn.SetNoDelay(true)
		if tlsConfig != nil {
			go p.handleConnection(tls.Server(conn, tlsConfig))
		} else {
			go p.handleConnection(conn)
		}
	}
}

func (p *ProxyListener) handleConnection(client net.Conn) {
	protocolPtr, headBytes := p.connectionDiscoverProtocol(client)
	
	var protocol string
	if protocolPtr == nil {
		protocol = p.FallbackProtocol
	} else {
		protocol = *protocolPtr
	}
	
	if p.Debug {
		log.Printf("Found protocol: %v", protocol)
	}
	
	protocolHost := p.ProtocolHosts[protocol]
	var server net.Conn
	var err error
	
	protocolAddr, err := net.ResolveTCPAddr("tcp", protocolHost.Host)
	if err != nil {
		log.Printf("Could not resolve backend: %v", err)
		return
	}
	
	
	switch protocolHost.Type {
		case "ssl": {
			var _server *net.TCPConn
			_server, err = net.DialTCP("tcp", nil, protocolAddr)
			if err == nil {
				_server.SetNoDelay(true)
				server = tls.Client(_server, nil)
			}
		}
		case "tcp": {
			var _server *net.TCPConn
			_server, err = net.DialTCP("tcp", nil, protocolAddr)
			_server.SetNoDelay(true)
			server = _server
		}
		default: {
			server, err = net.Dial(protocolHost.Type, protocolHost.Host)
		}
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
		if p.Debug {
			log.Printf("UN P B: %x %x %x %x %x %x %x", buff[0], buff[1], buff[2], buff[3], buff[4], buff[5], buff[6])
			log.Printf("UN P S: %s", buff[0:pos])
		}
		return nil, buff[0:pos]
	}

	return foundProtocol, buff[0:pos]
}