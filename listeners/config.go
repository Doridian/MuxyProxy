package listeners

import (
	"time"
	"os"
	"log"
	"sync/atomic"
	"crypto/tls"
	"encoding/json"
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
	
	FallbackProtocol *string
	
	ListenerAddress string
	
	Tls *[]ProxyTlsConfig
	ProtocolDiscoveryTimeout float64
}

type ProxyTlsConfig struct {
	Host string
	Certificate string
	PrivateKey string
}

var listenerIDAtomic = new(uint64)

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
		cListener.listenerID = atomic.AddUint64(listenerIDAtomic, 1)
		
		if cJSONSingle.FallbackProtocol != nil  {
			if _, ok := cJSONSingle.ProtocolHosts[*cJSONSingle.FallbackProtocol]; !ok {
				log.Fatalf("Could not load listener. Fallback protocol of %s specified but no handler present", *cJSONSingle.FallbackProtocol)
				continue
			}
		}
		
		if cJSONSingle.Tls != nil {
			cListener.Tls = new(tls.Config)
			for _, tlsHost := range *cJSONSingle.Tls {
				cert, err := tls.LoadX509KeyPair(tlsHost.Certificate, tlsHost.PrivateKey)
				if err != nil {
					log.Fatalf("[L#%d] Could not load keypair: %v", cListener.listenerID, err)
					continue
				}
				cListener.Tls.Certificates = append(cListener.Tls.Certificates, cert)
			}
		} else {
			cListener.Tls = nil
		}
		
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
		realListener := listener
		go realListener.Start()
	}
}
