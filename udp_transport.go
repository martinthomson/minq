package minq

import (
	"fmt"
	"net"
)

type UdpTransport struct {
	u *net.UDPConn
	r *net.UDPAddr
}

func (t *UdpTransport) SendTo(p []byte, r *net.UDPAddr) error {
	if r == nil {
		r = t.r
	}
	logf(logTypeUdp, "Sending message of len %v", len(p))
	n, err := t.u.WriteToUDP(p, r)
	if err != nil {
		return err
	}
	if n != len(p) {
		return fmt.Errorf("Incomplete write")
	}
	return nil
}

func (t *UdpTransport) SetRemoteAddr(r *net.UDPAddr) error {
	t.r = r
	return nil
}

func NewUdpTransport(u *net.UDPConn, r *net.UDPAddr) *UdpTransport {
	return &UdpTransport{u, r}
}

type UdpTransportFactory struct {
	local *net.UDPConn
}

func (f *UdpTransportFactory) MakeTransport(remote *net.UDPAddr) (Transport, error) {
	logf(logTypeUdp, "Making transport with remote addr %v", remote)
	return NewUdpTransport(f.local, remote), nil
}

func NewUdpTransportFactory(sock *net.UDPConn) *UdpTransportFactory {
	return &UdpTransportFactory{sock}
}
