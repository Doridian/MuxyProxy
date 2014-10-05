package listeners

import (
	"log"
	"net"
	"io"
	"fmt"
	"time"
	"strings"
	"bytes"
	"crypto/tls"
	"sync/atomic"
)

var connectionIDAtomic = new(uint64)

var htmlEndingDelimeters = [][]byte{[]byte("\r\n\r\n"),[]byte("\n\n")}
var muxyProxyHeader = []byte{0xFF,9,'M','u','x','y','P','r','o','x','y'}

type ProxyConnection struct {
	listener *ProxyListener
	client net.Conn
	server net.Conn
	remoteIP net.IP
}

func HandleNewConnection(listener *ProxyListener, client net.Conn) {
	c := new(ProxyConnection)
	c.listener = listener
	c.client = client
	
	if remoteAddrIP, ok := client.RemoteAddr().(*net.IPAddr); ok {
		c.remoteIP = remoteAddrIP.IP
	} else if remoteAddrTCP, ok := client.RemoteAddr().(*net.TCPAddr); ok {
		c.remoteIP = remoteAddrTCP.IP
	} else if remoteAddrUDP, ok := client.RemoteAddr().(*net.UDPAddr); ok {
		c.remoteIP = remoteAddrUDP.IP
	}
	
	c.handleConnection()
}

func (p *ProxyConnection) readConnUntil(headBytes *[]byte, delimeters [][]byte) bool {
	pos := len(*headBytes)
	
	defer p.client.SetDeadline(time.Unix(0, 0))
	
	for {
		for _, delim := range delimeters {
			if bytes.HasSuffix(*headBytes, delim) {
				return true
			}
		}
		p.client.SetDeadline(time.Now().Add(p.listener.ProtocolDiscoveryTimeout))
		readLen, err := p.client.Read((*headBytes)[pos:])
		if err != nil || readLen <= 0 {
			break
		}
		pos += readLen
	}
	return false
}

func (p *ProxyConnection) handleConnection() {
	defer p.client.Close()

	connectionID := atomic.AddUint64(connectionIDAtomic, 1)
	
	defer log.Printf("[L#%d] [C#%d] Closed", p.listener.listenerID, connectionID)
	
	log.Printf("[L#%d] [C#%d] Open from %v to %v", p.listener.listenerID, connectionID, p.remoteIP, p.client.LocalAddr())
	
	protocolPtr, headBytes := p.connectionDiscoverProtocol()
	
	var protocol string
	if protocolPtr == nil {
		if p.listener.FallbackProtocol == nil {
			log.Printf("[L#%d] [C#%d] Could not determine protocol and no fallback set", p.listener.listenerID, connectionID)
			return
		}
		protocol = *p.listener.FallbackProtocol
		log.Printf("[L#%d] [C#%d] Using fallback protocol: %s", p.listener.listenerID, connectionID, protocol)
	} else {
		protocol = *protocolPtr
		log.Printf("[L#%d] [C#%d] Protocol: %s", p.listener.listenerID, connectionID, protocol)
	}
	
	protocolHost := p.listener.ProtocolHosts[protocol]
	log.Printf("[L#%d] [C#%d] Connecting client to backend %s://%s (TLS: %t)", p.listener.listenerID, connectionID, protocolHost.Protocol, protocolHost.Host, protocolHost.Tls)
	
	var err error
	
	if protocolHost.IsTCP() {
		protocolAddr, err := net.ResolveTCPAddr(protocolHost.Protocol, protocolHost.Host)
		if err != nil {
			log.Printf("[L#%d] [C#%d] ERROR: Could not resolve backend: %v", p.listener.listenerID, connectionID, err)
			return
		}
		
		var _server *net.TCPConn
		_server, err = net.DialTCP(protocolHost.Protocol, nil, protocolAddr)
		if err == nil {
			_server.SetNoDelay(true)
			p.server = _server
		}
	} else {
		p.server, err = net.Dial(protocolHost.Protocol, protocolHost.Host)
	}
	
	if protocolHost.Tls {
		p.server = tls.Client(p.server, nil)
	}
	
	if err != nil {
		log.Printf("[L#%d] [C#%d] ERROR: Could not stablish backend connection: %v", p.listener.listenerID, connectionID, protocol, err)
		return
	}
	
	if p.remoteIP != nil {
		if protocol == "http" && protocolHost.Options["http_send_x_forwarded_for"] && p.readConnUntil(&headBytes, htmlEndingDelimeters) {
			if p.remoteIP != nil {
				headStr := string(headBytes)
				strData := strings.Split(headStr, "\n")
				strData = strData[:len(strData)-2]
				xFWFHeader := fmt.Sprintf("X-Forwarded-For: %v", p.remoteIP.String())
				foundXFWFHeader := false
				foundConnectionHeader := false
				for i, strLine := range strData {
					if len(strLine) > 16 && strings.ToLower(strLine[:16]) == "x-forwarded-for:" {
						strData[i] = xFWFHeader
						foundXFWFHeader = true
					} else if len(strLine) > 12 && strings.ToLower(strLine[:12]) == "connection:" {
						strData[i] = "Connection: close"
						foundConnectionHeader = true
					}
				}
				if !foundXFWFHeader {
					strData = append(strData, xFWFHeader)
				}
				if !foundConnectionHeader {
					strData = append(strData, "Connection: close")
				}
				strData = append(strData, "")
				strData = append(strData, "")
				strBytes := []byte(strings.Join(strData, "\n"))
				headBytes = strBytes
			}
		}
		
		if protocolHost.Options["send_real_ip"] {
			p.server.Write(muxyProxyHeader)
			p.server.Write([]byte{byte(len(p.remoteIP))})
			p.server.Write(p.remoteIP)
		}
	}
	
	p.server.Write(headBytes)
	
	go initiateCopy(p.server, p.client)
	initiateCopy(p.client, p.server)
}

func initiateCopy(from net.Conn, to net.Conn) {
	defer from.Close()
	defer to.Close()
	io.Copy(from, to)
}