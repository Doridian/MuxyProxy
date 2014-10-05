package listeners

import (
	"log"
	"net"
	"io"
	"crypto/tls"
	"sync/atomic"
)

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
	
	if protocolHost.IsTCP() {
		protocolAddr, err := net.ResolveTCPAddr(protocolHost.Protocol, protocolHost.Host)
		if err != nil {
			log.Printf("[L#%d] [C#%d] ERROR: Could not resolve backend: %v", listenerID, connectionID, err)
			return
		}
		
		var _server *net.TCPConn
		_server, err = net.DialTCP(protocolHost.Protocol, nil, protocolAddr)
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