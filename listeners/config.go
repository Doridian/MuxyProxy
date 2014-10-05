package listeners

import (
	"time"
	"os"
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
