package listeners

import (
	"time"
	"net"
	"log"
	"crypto/tls"
	"github.com/Doridian/MuxyProxy/utils"
	"github.com/Doridian/MuxyProxy/protocols"
)

type ProxyListener struct {
	FallbackProtocol *string
	
	ListenerAddress utils.AddressURL

	Tls *tls.Config
	
	ProtocolHosts map[string]utils.AddressURL
	
	ProtocolDiscoveryTimeout time.Duration
	config *protocols.ProxyProtocolConfig
	
	listenerID uint64
}

func (p *ProxyListener) Start() {
	var listener net.Listener
	var tcpListener *net.TCPListener
	var err error
	
	if p.ListenerAddress.IsTCP() {
		listenerAddr, err := net.ResolveTCPAddr(p.ListenerAddress.Protocol, p.ListenerAddress.Host)
		if err != nil {
			log.Printf("[L#%d] Could not resolve listener: %v", p.listenerID, err)
			return
		}
		tcpListener, err = net.ListenTCP(p.ListenerAddress.Protocol, listenerAddr)
	} else {
		listener, err = net.Listen(p.ListenerAddress.Protocol, p.ListenerAddress.Host)
	}
	
	if err != nil {
		log.Printf("[L#%d] Could not listen: %v", p.listenerID, err)
		return
	}
	
	log.Printf("[L#%d] Started listening on %s://%s (TLS: %t)", p.listenerID, p.ListenerAddress.Protocol, p.ListenerAddress.Host, p.ListenerAddress.Tls)
	defer log.Printf("[L#%d] Stopped listener", p.listenerID)
	
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
			log.Printf("[L#%d] Accept error: %v", p.listenerID, err)
			continue
		}
		
		if p.Tls != nil {
			go HandleNewConnection(p, tls.Server(conn, p.Tls))
		} else {
			go HandleNewConnection(p, conn)
		}
	}
}