package minq

// Server represents a QUIC server. A server can be fed an arbitrary
// number of packets and will create Connections as needed, passing
// each packet to the right connection.
type Server struct {
	handler      ServerHandler
	transFactory TransportFactory
	tls          *TlsConfig
	addrTable    map[string]*Connection
	idTable      map[string]*Connection
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
		conn = s.idTable[hdr.DestinationConnectionID.String()]
		if conn != nil {
			logf(logTypeServer, "Found by conn id")
		}
	}

	if conn == nil {
		conn = s.addrTable[addr.String()]
	}

	if conn == nil {
		logf(logTypeServer, "New server connection from addr %v", addr)
		conn = newServerConnection(s.transFactory, addr, s.tls)
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

		// TODO: have server connections manage their own entries in the table so
		// that they can use NEW_CONNECTION_ID and connection migration.
		s.idTable[conn.ServerId().String()] = conn
		s.addrTable[addr.String()] = conn
		if s.handler != nil {
			s.handler.NewConnection(conn)
		}
	}

	return conn, nil
}

// Check the server timers.
func (s *Server) CheckTimer() error {
	for _, conn := range s.idTable {
		_, err := conn.CheckTimer()
		if isFatalError(err) {
			logf(logTypeServer, "Fatal Error %v killing connection %v", err, conn)
			delete(s.idTable, conn.ServerId().String())
			// TODO(ekr@rtfm.com): Delete this from the addr table.
		}
	}
	return nil
}

// How many connections do we have?
func (s *Server) ConnectionCount() int {
	return len(s.idTable)
}

// Create a new QUIC server with the provide TLS config.
func NewServer(factory TransportFactory, tls *TlsConfig, handler ServerHandler) *Server {
	s := Server{
		handler,
		factory,
		tls,
		make(map[string]*Connection),
		make(map[string]*Connection),
	}
	s.tls.init()
	return &s
}
