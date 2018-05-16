package minq

import (
	"net"
	"testing"
	"time"
)

// fake TransportFactory that comes populated with
// a set of pre-fab transports keyed by name.
type testTransportFactoryMap struct {
	transports map[string]*testTransport
}

func (f *testTransportFactoryMap) MakeTransport(remote *net.UDPAddr) (Transport, error) {
	return f.transports[remote.String()], nil
}

func (f *testTransportFactoryMap) addTransport(remote *net.UDPAddr, t *testTransport) {
	f.transports[remote.String()] = t
}

func serverInputAll(t *testing.T, trans *testTransport, s *Server, srcAddr *net.UDPAddr) (*Connection, error) {
	var clast *Connection

	for {
		p, err := trans.Recv()
		if err != nil && err != ErrorWouldBlock {
			return nil, err
		}

		if p == nil {
			return clast, nil
		}

		c, err := s.Input(&UdpPacket{
			DestAddr: dummyAddr1,
			SrcAddr:  srcAddr,
			Data:     p,
		})
		if err != nil {
			return nil, err
		}

		if clast == nil {
			clast = c
		}
		assertEquals(t, c, clast)
	}
}

func TestServer(t *testing.T) {
	// Have the client and server do a handshake.
	cTrans, sTrans := newTestTransportPair(true)
	server := NewServer(sTrans, testTlsConfig(), nil)
	assertNotNil(t, server, "Couldn't make server")

	client := NewConnection(cTrans, dummyAddr1, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	n, err := client.CheckTimer()
	assertEquals(t, 1, n)
	assertNotError(t, err, "Couldn't send client initial")

	s1, err := serverInputAll(t, sTrans.t, server, dummyAddr2)
	assertNotError(t, err, "Couldn't consume client initial")

	err = inputAll(client)
	assertNotError(t, err, "Error processing SH")

	s2, err := serverInputAll(t, sTrans.t, server, dummyAddr2)
	assertNotError(t, err, "Error processing CFIN")
	// Make sure we get the same server back.
	assertEquals(t, s1, s2)

	// Now make a new client and ensure we get a different server connection
	cTrans2 := sTrans.newPairedTransport(true)
	client = NewConnection(cTrans2, dummyAddr1, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	n, err = client.CheckTimer()
	assertEquals(t, 1, n)
	assertNotError(t, err, "Couldn't send client initial")

	s3, err := serverInputAll(t, sTrans.t, server, dummyAddr3)
	assertNotError(t, err, "Couldn't consume client initial")

	assertX(t, s1 != s3, "Got the same server connection back with a different address")
	assertEquals(t, 2, len(server.addrTable))
}

func TestServerIdleTimeout(t *testing.T) {
	// Have the client and server do a handshake.
	cTrans, sTrans := newTestTransportPair(true)
	server := NewServer(sTrans, testTlsConfig(), nil)
	assertNotNil(t, server, "Couldn't make server")

	client := NewConnection(cTrans, dummyAddr1, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	n, err := client.CheckTimer()
	assertEquals(t, 1, n)
	assertNotError(t, err, "Couldn't send client initial")

	sconn, err := serverInputAll(t, sTrans.t, server, dummyAddr2)
	assertNotError(t, err, "Couldn't consume client initial")
	assertNotNil(t, sconn, "no server connection")

	assertEquals(t, 1, server.ConnectionCount())

	// This pokes into internal state of the server to avoid having to include
	// sleep calls in tests.  Don't do this at home kids.
	// Wind the timer on the connection back to short-circuit the idle timeout.
	sconn.lastInput = sconn.lastInput.Add(-1 - sconn.idleTimeout)
	server.CheckTimer()
	// A second nap to allow for draining period.
	sconn.closingEnd = sconn.closingEnd.Add(-1 - time.Second)
	server.CheckTimer()

	assertEquals(t, 0, server.ConnectionCount())
}
