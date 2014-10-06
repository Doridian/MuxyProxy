package listeners

import (
	"crypto/tls"
	"github.com/Doridian/MuxyProxy/protocols"
	"github.com/Doridian/MuxyProxy/utils"
	"log"
	"net"
	"time"
)

type ProxyListener struct {
	ID                       uint64
	FallbackProtocol         *string
	ListenerAddress          utils.AddressURL
	Tls                      *tls.Config
	ProtocolHosts            map[string]utils.AddressURL
	ProtocolDiscoveryTimeout time.Duration
	config                   *protocols.ProxyProtocolConfig
}

func (p *ProxyListener) Start() {
	var listener net.Listener
	var tcpListener *net.TCPListener
	var err error

	if p.ListenerAddress.IsTCP() {
		listenerAddr, err := net.ResolveTCPAddr(p.ListenerAddress.Protocol, p.ListenerAddress.Host)
		if err != nil {
			log.Printf("[L#%d] Could not resolve listener: %v", p.ID, err)
			return
		}
		tcpListener, err = net.ListenTCP(p.ListenerAddress.Protocol, listenerAddr)
	} else {
		listener, err = net.Listen(p.ListenerAddress.Protocol, p.ListenerAddress.Host)
	}

	if err != nil {
		log.Printf("[L#%d] Could not listen: %v", p.ID, err)
		return
	}

	log.Printf("[L#%d] Started listening on %s://%s (TLS: %t)", p.ID, p.ListenerAddress.Protocol, p.ListenerAddress.Host, p.ListenerAddress.Tls)
	defer log.Printf("[L#%d] Stopped listener", p.ID)

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
			log.Printf("[L#%d] Accept error: %v", p.ID, err)
			continue
		}

		if p.Tls != nil {
			go HandleNewConnection(p, tls.Server(conn, p.Tls))
		} else {
			go HandleNewConnection(p, conn)
		}
	}
}
