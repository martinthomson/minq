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
	// Send writes a packet.
	Send([]byte) error
}

// TransportFactory makes transports bound to a specific remote
// address.
type TransportFactory interface {
	// Make a transport object bound to |remote|.
	MakeTransport(remote *net.UDPAddr) (Transport, error)
}
