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

func (p *ProxyListener) readConnUntil(client net.Conn, headBytes *[]byte, delimeters [][]byte) bool {
	pos := len(*headBytes)
	
	defer client.SetDeadline(time.Unix(0, 0))
	
	for {
		for _, delim := range delimeters {
			if bytes.HasSuffix(*headBytes, delim) {
				return true
			}
		}
		client.SetDeadline(time.Now().Add(p.ProtocolDiscoveryTimeout))
		readLen, err := client.Read((*headBytes)[pos:])
		if err != nil || readLen <= 0 {
			break
		}
		pos += readLen
	}
	return false
}

func (p *ProxyListener) handleConnection(client net.Conn) {
	defer client.Close()

	connectionID := atomic.AddUint64(connectionIDAtomic, 1)
	
	defer log.Printf("[L#%d] [C#%d] Closed", p.listenerID, connectionID)
	
	log.Printf("[L#%d] [C#%d] Open from %v to %v", p.listenerID, connectionID, client.RemoteAddr(), client.LocalAddr())
	
	protocolPtr, headBytes := p.connectionDiscoverProtocol(client)
	
	var protocol string
	if protocolPtr == nil {
		if p.FallbackProtocol == nil {
			log.Printf("[L#%d] [C#%d] Could not determine protocol and no fallback set", p.listenerID, connectionID)
			return
		}
		protocol = *p.FallbackProtocol
		log.Printf("[L#%d] [C#%d] Using fallback protocol: %s", p.listenerID, connectionID, protocol)
	} else {
		protocol = *protocolPtr
		log.Printf("[L#%d] [C#%d] Protocol: %s", p.listenerID, connectionID, protocol)
	}
	
	protocolHost := p.ProtocolHosts[protocol]
	log.Printf("[L#%d] [C#%d] Connecting client to backend %s://%s (TLS: %t)", p.listenerID, connectionID, protocolHost.Protocol, protocolHost.Host, protocolHost.Tls)
	
	var server net.Conn
	var err error
	
	if protocolHost.IsTCP() {
		protocolAddr, err := net.ResolveTCPAddr(protocolHost.Protocol, protocolHost.Host)
		if err != nil {
			log.Printf("[L#%d] [C#%d] ERROR: Could not resolve backend: %v", p.listenerID, connectionID, err)
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
		log.Printf("[L#%d] [C#%d] ERROR: Could not stablish backend connection: %v", p.listenerID, connectionID, protocol, err)
		return
	}
	
	var remoteIP net.IP
	if remoteAddrIP, ok := client.RemoteAddr().(*net.IPAddr); ok {
		remoteIP = remoteAddrIP.IP
	} else if remoteAddrTCP, ok := client.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP = remoteAddrTCP.IP
	} else if remoteAddrUDP, ok := client.RemoteAddr().(*net.UDPAddr); ok {
		remoteIP = remoteAddrUDP.IP
	}
	
	if remoteIP != nil {
		if protocol == "http" && protocolHost.Options["http_send_x_forwarded_for"] && p.readConnUntil(client, &headBytes, htmlEndingDelimeters) {
			if remoteIP != nil {
				headStr := string(headBytes)
				strData := strings.Split(headStr, "\n")
				strData = strData[:len(strData)-2]
				xFWFHeader := fmt.Sprintf("X-Forwarded-For: %v", remoteIP.String())
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
			ipData := remoteIP
			server.Write(muxyProxyHeader)
			server.Write([]byte{byte(len(ipData))})
			server.Write(ipData)
		}
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