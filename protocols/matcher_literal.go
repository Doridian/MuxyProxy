package protocols

type protocolMatcherLiteral struct {
	protocolMatcherBase
	matchPattern []int
}

func (p *protocolMatcherLiteral) Matches(data []byte) bool {
	if len(data) < len(p.matchPattern) {
		return false
	}
	for i, b := range p.matchPattern {
		if b >= 0 && data[i] != byte(b) {
			return false
		}
	}
	return true
}