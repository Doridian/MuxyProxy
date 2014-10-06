package protocols

type ProtocolMatcher interface {
	Matches(data []byte) bool

	GetTarget() string
	GetProtocol() string

	setProtocol(protocol string)
	setTarget(target string)
}

type protocolMatcherBase struct {
	target   string
	protocol string
}

func (p *protocolMatcherBase) GetTarget() string {
	return p.target
}

func (p *protocolMatcherBase) GetProtocol() string {
	return p.protocol
}

func (p *protocolMatcherBase) setTarget(target string) {
	p.target = target
}

func (p *protocolMatcherBase) setProtocol(protocol string) {
	p.protocol = protocol
}
