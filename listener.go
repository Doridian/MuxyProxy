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
	"sync/atomic"
)

type ProxyListenerConfig struct {
	Debug bool
	Listeners []ProxyListener	
	config *ProxyProtocolConfig
}

type proxyListenerJSON struct {
	ProtocolHosts map[string]struct {
		Host string
		Type string
	}
	
	FallbackProtocol string
	ListenerAddress string
	Tls *[]ProxyTlsConfig
	ProtocolDiscoveryTimeout float64
}

type ProxyTlsConfig struct {
	Host string
	Certificate string
	PrivateKey string
}

type ProxyListener struct {
	Debug bool

	FallbackProtocol string
	ListenerAddress string

	Tls *[]ProxyTlsConfig
	
	ProtocolHosts map[string]struct {
		Host string
		Type string
	}
	
	ProtocolDiscoveryTimeout time.Duration
	config *ProxyProtocolConfig
}

func LoadListeners(file string, config *ProxyProtocolConfig, debug bool) *ProxyListenerConfig {
	var cJSON []proxyListenerJSON
	
	fileReader, err := os.Open(file)
	if err != nil {
		log.Panicf("Load CListeners: open err: %v", err)
	}	
	jsonReader := json.NewDecoder(fileReader)
	err = jsonReader.Decode(&cJSON)
	fileReader.Close()
	if err != nil {
		log.Panicf("Load CListeners: json err: %v", err)
	}
	
	log.Println("Load CListeners: OK")
	
	c := new(ProxyListenerConfig)
	c.Listeners = make([]ProxyListener, len(cJSON))
	for i, cJSONSingle := range cJSON {
		cListener := &c.Listeners[i]
		cListener.Debug = debug
		cListener.Tls = cJSONSingle.Tls
		cListener.FallbackProtocol = cJSONSingle.FallbackProtocol
		cListener.ListenerAddress = cJSONSingle.ListenerAddress
		cListener.ProtocolHosts = cJSONSingle.ProtocolHosts
		cListener.ProtocolDiscoveryTimeout = time.Duration(cJSONSingle.ProtocolDiscoveryTimeout) * time.Second
		cListener.config = new(ProxyProtocolConfig)
		
		cListener.config.LINE_PROTOCOLS_REGEXP = make(map[string]*regexp.Regexp)
		cListener.config.LINE_PROTOCOLS_LITERAL = make(map[string][]int)
		cListener.config.RAW_PROTOCOLS_REGEXP = make(map[string]*regexp.Regexp)
		cListener.config.RAW_PROTOCOLS_LITERAL = make(map[string][]int)
		
		for protocol, _ := range cJSONSingle.ProtocolHosts {
			a, ok := config.LINE_PROTOCOLS_REGEXP[protocol]
			if ok {
				cListener.config.LINE_PROTOCOLS_REGEXP[protocol] = a
			}
			b,ok := config.LINE_PROTOCOLS_LITERAL[protocol]
			if ok {
				cListener.config.LINE_PROTOCOLS_LITERAL[protocol] = b
			}
			c, ok := config.RAW_PROTOCOLS_REGEXP[protocol]
			if ok {
				cListener.config.RAW_PROTOCOLS_REGEXP[protocol] = c
			}
			d, ok := config.RAW_PROTOCOLS_LITERAL[protocol]
			if ok {
				cListener.config.RAW_PROTOCOLS_LITERAL[protocol] = d
			}
		}
	}
	c.config = config
	c.Debug = debug
	
	return c
}

func (c *ProxyListenerConfig) Start() {
	for _,listener := range c.Listeners {
		go listener.Start()
	}
}

var listenerIDAtomic = new(uint64)

func (p *ProxyListener) Start() {
	listenerID := atomic.AddUint64(listenerIDAtomic, 1)

	listenerAddr, err := net.ResolveTCPAddr("tcp", p.ListenerAddress)
	if err != nil {
		log.Printf("[L#%d] Could not resolve listener: %v", listenerID, err)
		return
	}
	
	listener, err := net.ListenTCP("tcp", listenerAddr)
	if err != nil {
		log.Printf("[L#%d] Could not listen: %v", listenerID, err)
		return
	}
	
	log.Printf("[L#%d] Started listening on tcp://%v", listenerID, listenerAddr)
	defer log.Printf("[L#%d] Stopped listener", listenerID)
	
	var tlsConfig *tls.Config
	if p.Tls != nil {
		tlsConfig = new(tls.Config)
		for _, tlsHost := range *p.Tls {
			cert, err := tls.LoadX509KeyPair(tlsHost.Certificate, tlsHost.PrivateKey)
			if err != nil {
				log.Printf("[L#%d] Could not load keypair: %v", listenerID, err)
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
			log.Printf("[L#%d] Accept error: %v", listenerID, err)
			continue
		}
		
		conn.SetNoDelay(true)
		if tlsConfig != nil {
			go p.handleConnection(listenerID, tls.Server(conn, tlsConfig))
		} else {
			go p.handleConnection(listenerID, conn)
		}
	}
}

var connectionIDAtomic = new(uint64)

func (p *ProxyListener) handleConnection(listenerID uint64, client net.Conn) {
	defer client.Close()

	connectionID := atomic.AddUint64(connectionIDAtomic, 1)
	
	defer log.Printf("[L#%d] [C#%d] Closed", listenerID, connectionID)
	
	log.Printf("[L#%d] [C#%d] Open from %v to %v", listenerID, connectionID, client.RemoteAddr(), client.LocalAddr())
	
	protocolPtr, headBytes := p.connectionDiscoverProtocol(client)
	
	var protocol string
	if protocolPtr == nil {
		protocol = p.FallbackProtocol
		log.Printf("[L#%d] [C#%d] Using fallback protocol: %s", listenerID, connectionID, protocol)
	} else {
		protocol = *protocolPtr
		log.Printf("[L#%d] [C#%d] Protocol: %s", listenerID, connectionID, protocol)
	}
	
	protocolHost := p.ProtocolHosts[protocol]
	log.Printf("[L#%d] [C#%d] Connecting client to backend %s://%s", listenerID, connectionID, protocolHost.Type, protocolHost.Host)
	
	var server net.Conn
	var err error
	
	protocolAddr, err := net.ResolveTCPAddr("tcp", protocolHost.Host)
	if err != nil {
		log.Printf("[L#%d] [C#%d] ERROR: Could not resolve backend: %v", listenerID, connectionID, err)
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
		log.Printf("[L#%d] [C#%d] ERROR: Could not stablish backend connection: %v", listenerID, connectionID, protocol, err)
		return
	}
	
	server.Write(headBytes)
	
	go io.Copy(server, client)
	io.Copy(client, server)
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
		for protocol,literal := range p.config.LINE_PROTOCOLS_LITERAL {
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
		for protocol,regexp := range p.config.LINE_PROTOCOLS_REGEXP {
			if regexp.Match(firstLine) {
				return &protocol
			}
		}
	}
	
	for protocol,literal := range p.config.RAW_PROTOCOLS_LITERAL {
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
	for protocol,regexp := range p.config.RAW_PROTOCOLS_REGEXP {
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
		conn.SetDeadline(time.Now().Add(p.ProtocolDiscoveryTimeout))
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