package listeners

import (
	"time"
	"log"
	"net"
	"io"
	"crypto/tls"
	"os"
	"encoding/json"
	"sync/atomic"
	"github.com/Doridian/MuxyProxy/utils"
	"github.com/Doridian/MuxyProxy/protocols"
)

var _PROTOCOL_DEBUG = true

type ProxyListenerConfig struct {
	Listeners []ProxyListener	
	config *protocols.ProxyProtocolConfig
}

type proxyListenerJSON struct {
	ProtocolHosts map[string]string
	
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
	FallbackProtocol string
	
	ListenerAddress utils.FullAddress

	Tls *[]ProxyTlsConfig
	
	ProtocolHosts map[string]utils.FullAddress
	
	ProtocolDiscoveryTimeout time.Duration
	config *protocols.ProxyProtocolConfig
}

func Load(file string, config *protocols.ProxyProtocolConfig) (*ProxyListenerConfig, error) {
	var cJSON []proxyListenerJSON
	
	fileReader, err := os.Open(file)
	if err != nil {
		return nil, err
	}	
	jsonReader := json.NewDecoder(fileReader)
	err = jsonReader.Decode(&cJSON)
	fileReader.Close()
	if err != nil {
		return nil, err
	}
	
	c := new(ProxyListenerConfig)
	c.Listeners = make([]ProxyListener, len(cJSON))
	for i, cJSONSingle := range cJSON {
		cListener := &c.Listeners[i]
		cListener.Tls = cJSONSingle.Tls
		cListener.FallbackProtocol = cJSONSingle.FallbackProtocol
		cListener.ListenerAddress = utils.DecodeAddressURL(cJSONSingle.ListenerAddress)
		cListener.ProtocolHosts = make(map[string]utils.FullAddress)
		for protocol, addressURL := range cJSONSingle.ProtocolHosts {
			cListener.ProtocolHosts[protocol] = utils.DecodeAddressURL(addressURL)
		}
		
		cListener.ProtocolDiscoveryTimeout = time.Duration(cJSONSingle.ProtocolDiscoveryTimeout) * time.Second
		cListener.config = new(protocols.ProxyProtocolConfig)
		
		cListener.config.Matchers = make([]protocols.ProtocolMatcher, 0)
		for _, matcher := range config.Matchers {
			_, ok := cJSONSingle.ProtocolHosts[matcher.GetProtocol()]
			if ok {
				cListener.config.Matchers = append(cListener.config.Matchers, matcher)
			}
		}
	}
	c.config = config
	
	return c, nil
}

func (c *ProxyListenerConfig) Start() {
	for _,listener := range c.Listeners {
		go listener.Start()
	}
}

var listenerIDAtomic = new(uint64)

func (p *ProxyListener) Start() {
	listenerID := atomic.AddUint64(listenerIDAtomic, 1)

	var listener net.Listener
	var tcpListener *net.TCPListener
	var err error
	
	if p.ListenerAddress.Protocol == "tcp" {
		listenerAddr, err := net.ResolveTCPAddr("tcp", p.ListenerAddress.Host)
		if err != nil {
			log.Printf("[L#%d] Could not resolve listener: %v", listenerID, err)
			return
		}
		tcpListener, err = net.ListenTCP("tcp", listenerAddr)
	} else {
		listener, err = net.Listen(p.ListenerAddress.Protocol, p.ListenerAddress.Host)
	}
	
	if err != nil {
		log.Printf("[L#%d] Could not listen: %v", listenerID, err)
		return
	}
	
	log.Printf("[L#%d] Started listening on %s://%s (TLS: %t)", listenerID, p.ListenerAddress.Protocol, p.ListenerAddress.Host, p.ListenerAddress.Tls)
	defer log.Printf("[L#%d] Stopped listener", listenerID)
	
	var tlsConfig *tls.Config
	if p.ListenerAddress.Tls {
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
		var conn net.Conn
		if tcpListener != nil {
			var tcpConn *net.TCPConn
			tcpConn, err = tcpListener.AcceptTCP()
			if err == nil {
				tcpConn.SetNoDelay(true)
			}
			conn = tcpConn
		} else {
			conn, err = listener.Accept()
		}
		if err != nil {
			log.Printf("[L#%d] Accept error: %v", listenerID, err)
			continue
		}
		
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
	log.Printf("[L#%d] [C#%d] Connecting client to backend %s://%s (TLS: %t)", listenerID, connectionID, protocolHost.Protocol, protocolHost.Host, protocolHost.Tls)
	
	var server net.Conn
	var err error
	
	protocolAddr, err := net.ResolveTCPAddr("tcp", protocolHost.Host)
	if err != nil {
		log.Printf("[L#%d] [C#%d] ERROR: Could not resolve backend: %v", listenerID, connectionID, err)
		return
	}
	
	if protocolHost.Protocol == "tcp" {
		var _server *net.TCPConn
		_server, err = net.DialTCP("tcp", nil, protocolAddr)
		if err == nil {
			_server.SetNoDelay(true)
			server = _server
		}
	} else {
		server, err = net.Dial(protocolHost.Protocol, protocolHost.Host)
	}
	
	if protocolHost.Tls {
		server = tls.Client(server, nil)
	}
	
	if err != nil {
		log.Printf("[L#%d] [C#%d] ERROR: Could not stablish backend connection: %v", listenerID, connectionID, protocol, err)
		return
	}
	
	server.Write(headBytes)
	
	go initiateCopy(server, client)
	initiateCopy(client, server)
}

func initiateCopy(from net.Conn, to net.Conn) {
	defer from.Close()
	defer to.Close()
	io.Copy(from, to)
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
	
	for _, matcher := range p.config.Matchers {
		var _matchData []byte
		switch(matcher.GetTarget()) {
			case "line": {
				if !hasNewline {
					continue
				}
				_matchData = firstLine
			}
			case "raw": {
				_matchData = data
			}
		}
		if matcher.Matches(_matchData) {
			proto := matcher.GetProtocol()
			return &proto
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
		if _PROTOCOL_DEBUG {
			log.Printf("UN P B: %x %x %x %x %x %x %x", buff[0], buff[1], buff[2], buff[3], buff[4], buff[5], buff[6])
			log.Printf("UN P S: %s", buff[0:pos])
		}
		return nil, buff[0:pos]
	}

	return foundProtocol, buff[0:pos]
}