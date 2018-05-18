package minq

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

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
	serverTransport := sTrans.t
	server := NewServer(sTrans, testTlsConfig(), nil)
	assertNotNil(t, server, "Couldn't make server")

	client := NewConnection(cTrans, dummyAddr1, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	n, err := client.CheckTimer()
	assertEquals(t, 1, n)
	assertNotError(t, err, "Couldn't send client initial")

	s1, err := serverInputAll(t, serverTransport, server, dummyAddr2)
	assertNotError(t, err, "Couldn't consume client initial")

	err = inputAll(client)
	assertNotError(t, err, "Error processing SH")

	s2, err := serverInputAll(t, serverTransport, server, dummyAddr2)
	assertNotError(t, err, "Error processing CFIN")
	// Make sure we get the same server back.
	assertEquals(t, s1, s2)

	// Now make a new client and ensure we get a different server connection
	cTrans2 := sTrans.newPairedTransport(true)
	serverTransport = sTrans.t
	client = NewConnection(cTrans2, dummyAddr1, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	n, err = client.CheckTimer()
	assertEquals(t, 1, n)
	assertNotError(t, err, "Couldn't send client initial")

	s3, err := serverInputAll(t, serverTransport, server, dummyAddr3)
	assertNotError(t, err, "Couldn't consume client initial")

	assertX(t, s1 != s3, "Got the same server connection back with a different address")
	assertEquals(t, 2, server.ConnectionCount())
}

func TestServerIdleTimeout(t *testing.T) {
	// Have the client and server do a handshake.
	cTrans, sTrans := newTestTransportPair(true)
	serverTransport := sTrans.t
	server := NewServer(sTrans, testTlsConfig(), nil)
	assertNotNil(t, server, "Couldn't make server")

	client := NewConnection(cTrans, dummyAddr1, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	n, err := client.CheckTimer()
	assertEquals(t, 1, n)
	assertNotError(t, err, "Couldn't send client initial")

	sconn, err := serverInputAll(t, serverTransport, server, dummyAddr2)
	assertNotError(t, err, "Couldn't consume client initial")
	assertNotNil(t, sconn, "no server connection")

	assertEquals(t, 1, server.ConnectionCount())

	// This pokes into internal state of the server to avoid having to include
	// sleep calls in tests.  Don't do this at home kids.
	// Wind the timer on the connection back to short-circuit the idle timeout.
	sconn.lastInput = sconn.lastInput.Add(-1 - sconn.idleTimeout)
	err = server.CheckTimer()
	assertNotError(t, err, "should still be closing")
	// A second nap to allow for draining period.
	sconn.closingEnd = sconn.closingEnd.Add(-1 - time.Second)
	err = server.CheckTimer()
	assertEquals(t, err, ErrorConnIsClosed)

	assertEquals(t, 0, server.ConnectionCount())
}

func serverConnect(t *testing.T, client *Connection, server *Server, serverTransport *testTransport) *Connection {
	n, err := client.CheckTimer()
	assertEquals(t, 1, n)
	assertNotError(t, err, "Couldn't send client initial")

	s1, err := serverInputAll(t, serverTransport, server, dummyAddr2)
	assertNotError(t, err, "Couldn't consume client initial")

	err = inputAll(client)
	assertNotError(t, err, "Error processing SH")

	s2, err := serverInputAll(t, serverTransport, server, dummyAddr2)
	assertNotError(t, err, "Error processing CFIN")
	// Make sure we get the same server back.
	assertEquals(t, s1, s2)

	assertEquals(t, client.GetState(), StateEstablished)
	assertEquals(t, s2.GetState(), StateEstablished)
	return s2
}

func TestServerStatelessReset(t *testing.T) {
	cTrans, sTrans := newTestTransportPair(true)
	clientTransport := cTrans.t
	serverTransport := sTrans.t
	server := NewServer(sTrans, testTlsConfig(), nil)
	assertNotNil(t, server, "Couldn't make server")

	client := NewConnection(cTrans, dummyAddr1, testTlsConfig(), nil)
	assertNotNil(t, client, "Couldn't make client")

	serverConnection := serverConnect(t, client, server, serverTransport)

	cid := serverConnection.ServerId()
	resetToken := client.currentPath.resetToken
	assertEquals(t, len(resetToken), 16)

	// Now close at the server end, but prevent the message from propagating.
	serverTransport.w.autoFlush = false
	serverConnection.Close()
	drain(t, serverConnection)
	assertEquals(t, 0, server.ConnectionCount())

	// Make a packet that seems to be for the now-removed connection.
	var statelessReset bytes.Buffer
	_, err := statelessReset.Write([]byte{byte(packetFlagShortHeader)})
	assertNotError(t, err, "set first octet")
	_, err = io.Copy(&statelessReset, bytes.NewReader(cid))
	assertNotError(t, err, "copy cid in")
	_, err = io.CopyN(&statelessReset, rand.Reader, 22)
	assertNotError(t, err, "random reading")
	_, err = io.Copy(&statelessReset, bytes.NewReader(resetToken))
	assertNotError(t, err, "append reset token")

	// Make a new transport for the server, ignore the client side and just
	// read the stateless reset from the buffer on the server side.
	_ = sTrans.newPairedTransport(false)
	serverTransport = sTrans.t

	_, err = server.Input(&UdpPacket{
		DestAddr: dummyAddr1,
		SrcAddr:  dummyAddr2,
		Data:     statelessReset.Bytes(),
	})
	assertError(t, err, "should generate an error")
	assertEquals(t, len(serverTransport.w.in), 1)
	packet := serverTransport.w.in[0].b
	assertByteEquals(t, packet[len(packet)-len(resetToken):], resetToken)

	// Now reset the client's input queue to include just the stateless reset
	// and let the client consume the reset.
	clientTransport.r.out = serverTransport.w.in
	err = inputAll(client)
	assertEquals(t, err, ErrorStatelessReset)

	// Finally, ensure that a too-short packet doesn't cause the server to
	// send a stateless reset.
	_ = sTrans.newPairedTransport(false)
	_, err = server.Input(&UdpPacket{
		DestAddr: dummyAddr1,
		SrcAddr:  dummyAddr2,
		Data:     statelessReset.Bytes()[:18+len(cid)],
	})
	assertError(t, err, "should generate an error")
	// Should have sent nothing though.
	assertNotNil(t, sTrans.t, "the transport at the server should be unused")
}
