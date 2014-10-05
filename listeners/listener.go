package listeners

import (
	"time"
	"net"
	"log"
	"crypto/tls"
	"sync/atomic"
	"github.com/Doridian/MuxyProxy/utils"
	"github.com/Doridian/MuxyProxy/protocols"
)

type ProxyListener struct {
	FallbackProtocol *string
	
	ListenerAddress utils.FullAddress

	Tls *[]ProxyTlsConfig
	
	ProtocolHosts map[string]utils.FullAddress
	
	ProtocolDiscoveryTimeout time.Duration
	config *protocols.ProxyProtocolConfig
}

var listenerIDAtomic = new(uint64)

func (p *ProxyListener) Start() {
	listenerID := atomic.AddUint64(listenerIDAtomic, 1)

	var listener net.Listener
	var tcpListener *net.TCPListener
	var err error
	
	if p.ListenerAddress.IsTCP() {
		listenerAddr, err := net.ResolveTCPAddr(p.ListenerAddress.Protocol, p.ListenerAddress.Host)
		if err != nil {
			log.Printf("[L#%d] Could not resolve listener: %v", listenerID, err)
			return
		}
		tcpListener, err = net.ListenTCP(p.ListenerAddress.Protocol, listenerAddr)
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