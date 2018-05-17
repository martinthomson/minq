package minq

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"io"
	"net"
)

// The number of octets we can receive before we sent a stateless reset.
// This the minimal header (our cid length plus 1 each for first octet and PN),
// Plus one octet of content and an integrity check (which we assume isn't
// smaller than the initial integrity check of 16).
const kStatelessResetMinimum = 2 + kCidDefaultLength + 1 + kInitialIntegrityCheckLength

type connectionTable struct {
	idTable        map[string]*Connection
	addrTable      map[string]*Connection
	resetTokenHmac hash.Hash
}

func (ct *connectionTable) Put(cid ConnectionId, remoteAddr *net.UDPAddr, c *Connection) bool {
	if !ct.PutCid(cid, c) {
		return false
	}
	ct.PutRemoteAddr(remoteAddr, c)
	return true
}

func (ct *connectionTable) PutCid(cid ConnectionId, c *Connection) bool {
	_, present := ct.idTable[cid.String()]
	if present {
		// The connection ID has to be unique.
		return false
	}
	ct.idTable[cid.String()] = c
	return true
}

// Address is not guaranteed unique, if there is a collision, then any existing entry
// is removed to avoid confusion.
func (ct *connectionTable) PutRemoteAddr(remoteAddr *net.UDPAddr, c *Connection) {
	_, present := ct.addrTable[remoteAddr.String()]
	if present {
		delete(ct.addrTable, remoteAddr.String())
	} else {
		// The remote address is a fallback.
		ct.addrTable[remoteAddr.String()] = c
	}
}

func (ct *connectionTable) Get(cid ConnectionId) *Connection {
	return ct.idTable[cid.String()]
}

func (ct *connectionTable) GetAddr(remoteAddr *net.UDPAddr) *Connection {
	return ct.addrTable[remoteAddr.String()]
}

func (ct *connectionTable) Remove(cid ConnectionId, remoteAddr *net.UDPAddr) {
	ct.RemoveCid(cid)
	delete(ct.addrTable, remoteAddr.String())
}

func (ct *connectionTable) RemoveCid(cid ConnectionId) {
	delete(ct.idTable, cid.String())
}

func (ct *connectionTable) GenerateResetToken(cid ConnectionId) ([]byte, error) {
	if ct.resetTokenHmac == nil {
		k := make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, k)
		if err != nil {
			return nil, err
		}
		ct.resetTokenHmac = hmac.New(sha256.New, k)
	}
	return ct.resetTokenHmac.Sum([]byte(cid))[0:16], nil
}

// All runs the provided function on all connections.  This exits early on error.
func (t *connectionTable) All(f func(*Connection) error) error {
	for _, c := range t.idTable {
		err := f(c)
		if err != nil {
			return err
		}
	}
	return nil
}

// Server represents a QUIC server. A server can be fed an arbitrary
// number of packets and will create Connections as needed, passing
// each packet to the right connection.
type Server struct {
	handler      ServerHandler
	transFactory TransportFactory
	tls          *TlsConfig
	table        connectionTable
}

// Interface for the handler object which the Server will call
// to notify of events.
type ServerHandler interface {
	// A new connection has been created and can be found in |c|.
	NewConnection(c *Connection)
}

// SetHandler sets a handler function.
func (s *Server) SetHandler(h ServerHandler) {
	s.handler = h
}

// Input passes an incoming packet to the Server.
func (s *Server) Input(packet *UdpPacket) (*Connection, error) {
	addr := packet.SrcAddr
	logf(logTypeServer, "Received packet from %v", addr)
	hdr := packetHeader{shortCidLength: kCidDefaultLength}
	newConn := false

	data := packet.Data
	_, err := decode(&hdr, data)
	if err != nil {
		return nil, err
	}

	var conn *Connection

	if len(hdr.DestinationConnectionID) > 0 {
		logf(logTypeServer, "Received conn id %v", hdr.DestinationConnectionID)
		conn = s.table.Get(hdr.DestinationConnectionID)
		if conn != nil {
			logf(logTypeServer, "Found by conn id")
		}
	}

	if conn == nil {
		conn = s.table.GetAddr(addr)
	}

	if conn == nil {
		if !hdr.Type.isLongHeader() {
			logf(logTypeServer, "Short header packet for unknown connection")
			if len(data) >= kStatelessResetMinimum {
				err = s.sendStatelessReset(hdr.DestinationConnectionID, addr)
				if err != nil {
					logf(logTypeServer, "error sending stateless reset")
				}
			}
			return nil, fatalError("stateless reset sent")
		}

		logf(logTypeServer, "New server connection from addr %v", addr)
		conn = newServerConnection(s.transFactory, addr, s.tls, &s.table)
		if conn == nil {
			return nil, fatalError("unable to create server")
		}
		newConn = true
	}

	err = conn.Input(packet)
	if isFatalError(err) {
		logf(logTypeServer, "Fatal Error %v killing connection %v", err, conn)
		return nil, nil
	}

	if newConn {
		// Wait until handling the first packet before the connection is added
		// to the table.  Firstly, to avoid having to remove it if there is an
		// error, but also because the server-chosen connection ID isn't set
		// until after the Initial is handled.
		if s.handler != nil {
			s.handler.NewConnection(conn)
		}
	}

	return conn, nil
}

func (s *Server) sendStatelessReset(cid ConnectionId, remoteAddr *net.UDPAddr) error {
	token, err := s.table.GenerateResetToken(cid)
	if err != nil {
		return err
	}
	// We have to assume that the peer wanted a maximum-sized connection ID,
	//  that means that the packet will be at least 21 octets without the
	// integrity check (1 for first octet, 1 for packet number, 1 for some content).
	// Assume that the integrity check is 16 octets, which is the same size as the
	// reset token.
	sr := make([]byte, 21)
	_, err = io.ReadFull(rand.Reader, sr)
	if err != nil {
		return err
	}
	// Add up to another 15 octets, using randomness from the first octet,
	// which is then replaced so that this looks like a short header.
	extra := make([]byte, int(sr[0]&0xf))
	_, err = io.ReadFull(rand.Reader, extra)
	if err != nil {
		return err
	}
	// Keep the random K and add the short header flags.
	sr[0] = (sr[0] & byte(packetFlagK)) | byte(packetFlagShortHeader)
	sr = append(sr, append(extra, token...)...)

	t, err := s.transFactory.MakeTransport(remoteAddr)
	if err != nil {
		return err
	}
	return t.Send(sr)
}

// Check the server timers.
func (s *Server) CheckTimer() error {
	return s.table.All(func(conn *Connection) error {
		_, err := conn.CheckTimer()
		if isFatalError(err) {
			logf(logTypeServer, "Fatal Error %v killing connection %v", err, conn)
			return err
		}
		return nil
	})
}

// How many connections do we have?
func (s *Server) ConnectionCount() int {
	uniqueConnections := make(map[string]struct{})
	s.table.All(func(conn *Connection) error {
		uniqueConnections[conn.ServerId().String()] = struct{}{}
		return nil
	})
	return len(uniqueConnections)
}

// Create a new QUIC server with the provide TLS config.
func NewServer(factory TransportFactory, tls *TlsConfig, handler ServerHandler) *Server {
	s := Server{
		handler:      handler,
		transFactory: factory,
		tls:          tls,
		table: connectionTable{
			idTable:   make(map[string]*Connection),
			addrTable: make(map[string]*Connection),
		},
	}
	s.tls.init()
	return &s
}
