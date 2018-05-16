package minq

import "net"

// UdpPacket describes a UDP packet.
type UdpPacket struct {
	DestAddr *net.UDPAddr
	SrcAddr  *net.UDPAddr
	Data     []byte
}

// Transport for sending packets. Each Transport
// is bound to some particular remote address (or in testing
// we just use a mock which sends the packet into a queue).
type Transport interface {
	// SendTo writes to a specific remote address without changing the default.
	// If the |r| is nil, then this must use the current remote address.
	SendTo([]byte, *net.UDPAddr) error
	// SetRemoteAddr causes all subsequent writes to go to a new remote address.
	SetRemoteAddr(*net.UDPAddr) error
}

// TransportFactory makes transports bound to a specific remote
// address.
type TransportFactory interface {
	// Make a transport object bound to |remote|.
	MakeTransport(remote *net.UDPAddr) (Transport, error)
}
