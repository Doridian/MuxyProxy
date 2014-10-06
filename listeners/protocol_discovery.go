package listeners

import (
	"time"
	"log"
	"bytes"
)

func (p *ProxyConnection) whichProtocolIs(data []byte, dataLen int) (*string, []byte, int) {
	if dataLen  < 1 {
		return nil, data, dataLen
	}
	actualData := data[0:dataLen]
	
	if p.listener.ListenerAddress.Options["send_real_ip"] && bytes.HasPrefix(data, muxyProxyHeader) {
		basePos := len(muxyProxyHeader)
		if basePos > dataLen {
			return nil, data, dataLen
		}
		ipLen := int(data[basePos])
		basePos++
		if basePos + ipLen > dataLen {
			return nil, data, dataLen
		}
		p.remoteIP = data[basePos:basePos+ipLen]
		data = data[basePos+ipLen:]
		dataLen -= basePos+ipLen
		log.Printf("[L#%d] [C#%d] Forward packet got %v", p.listener.ID, p.ID, p.remoteIP)
	}

	hasNewline := false
	firstLine := make([]byte, 0)
	for i,b := range actualData {
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
	
	for _, matcher := range p.listener.config.Matchers {
		var _matchData []byte
		switch(matcher.GetTarget()) {
			case "line": {
				if !hasNewline {
					continue
				}
				_matchData = firstLine
			}
			case "raw": {
				_matchData = actualData
			}
		}
		if matcher.Matches(_matchData) {
			proto := matcher.GetProtocol()
			return &proto, data, dataLen
		}
	}
	
	return nil, data, dataLen
}

func (p *ProxyConnection) connectionDiscoverProtocol() (*string, []byte) {
	defer p.client.SetDeadline(time.Unix(0, 0))
	
	buff := make([]byte, 8192)
	pos := 0
	var foundProtocol *string
	for {
		p.client.SetDeadline(time.Now().Add(p.listener.ProtocolDiscoveryTimeout))
		readLen, err := p.client.Read(buff[pos:])
		if err != nil || readLen <= 0 {
			break
		}
		pos += readLen
		
		foundProtocol, buff, pos = p.whichProtocolIs(buff, pos)
		if foundProtocol != nil {
			return foundProtocol, buff[0:pos]
		}
	}
	
	foundProtocol, buff, pos = p.whichProtocolIs(buff, pos)
	
	if foundProtocol == nil {
		if _PROTOCOL_DEBUG {
			log.Printf("UN P B: %x %x %x %x %x %x %x", buff[0], buff[1], buff[2], buff[3], buff[4], buff[5], buff[6])
			log.Printf("UN P S: %s", buff[0:pos])
		}
		return nil, buff[0:pos]
	}

	return foundProtocol, buff[0:pos]
}