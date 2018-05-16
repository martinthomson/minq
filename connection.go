/*
Package minq is a minimal implementation of QUIC, as documented at
https://quicwg.github.io/. Minq partly implements draft-04.

*/
package minq

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"time"

	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
)

// Role determines whether an endpoint is client or server.
type Role uint8

// These are roles.
const (
	RoleClient = Role(1)
	RoleServer = Role(2)
)

// State is the state of a QUIC connection.
type State uint8

// These are connection states.
const (
	StateInit                   = State(1)
	StateWaitClientInitial      = State(2)
	StateWaitServerFirstFlight  = State(3)
	StateWaitClientSecondFlight = State(4)
	StateEstablished            = State(5)
	StateClosing                = State(6)
	StateClosed                 = State(7)
	StateError                  = State(8)
)

const (
	kMinimumClientInitialLength  = 1200 // draft-ietf-quic-transport S 9.0
	kLongHeaderLength            = 12   // omits connection ID lengths
	kInitialIntegrityCheckLength = 16   // Overhead.
	kInitialMTU                  = 1252 // 1280 - UDP headers.
)

// The protocol version number.
type VersionNumber uint32

const (
	kQuicDraftVersion   = 11
	kQuicVersion        = VersionNumber(0xff000000 | kQuicDraftVersion)
	kQuicGreaseVersion1 = VersionNumber(0x1a1a1a1a)
	kQuicGreaseVersion2 = VersionNumber(0x2a2a2a2a)
)

const (
	kQuicALPNToken = "hq-11"
)

// Interface for the handler object which the Connection will call
// to notify of events on the connection.
type ConnectionHandler interface {
	// The connection has changed state to state |s|
	StateChanged(s State)

	// NewRecvStream indicates that a new unidirectional stream has been
	// created by the remote peer. |s| contains the stream.
	NewRecvStream(s RecvStream)

	// NewStream indicates that a new bidirectional stream has been
	// created by the remote peer. |s| contains the stream.
	NewStream(s Stream)

	// StreamReadable indicates that |s| is now readable.
	StreamReadable(s RecvStream)
}

// Internal structures indicating ranges to ACK
type ackRange struct {
	lastPacket uint64 // Packet with highest pn in range
	count      uint64 // Total number of packets in range
}

type ackRanges []ackRange

type path struct {
	remoteConnectionId ConnectionId
	localConnectionId  ConnectionId
	transport          Transport
	congestion         CongestionController
}

func (p *path) String() string {
	return fmt.Sprintf("%v_%v", p.localConnectionId, p.remoteConnectionId)
}

func (p *path) Send(pn uint64, packet []byte, ackOnly bool) error {
	p.congestion.onPacketSent(pn, ackOnly, len(packet))
	return p.transport.Send(packet)
}

/*
Connection represents a QUIC connection. Clients can make
connections directly but servers should create a minq.Server
object which creates Connections as a side effect.

The control discipline is entirely operated by the consuming
application. It has two major responsibilities:

  1. Deliver any incoming datagrams using Input()
  2. Periodically call CheckTimer(). In future there will be some
     way to know how often to call it, but right now it treats
     every call to CheckTimer() as timer expiry.

The application provides a handler object which the Connection
calls to notify it of various events.
*/
type Connection struct {
	handler            ConnectionHandler
	role               Role
	state              State
	version            VersionNumber
	currentPath        *path
	paths              map[string]*path
	transportFactory   TransportFactory
	tls                *tlsConn
	writeClear         *cryptoState
	readClear          *cryptoState
	writeProtected     *cryptoState
	readProtected      *cryptoState
	nextSendPacket     uint64
	mtu                int
	stream0            *stream
	localBidiStreams   *streamSet
	remoteBidiStreams  *streamSet
	localUniStreams    *streamSet
	remoteUniStreams   *streamSet
	outputClearQ       []frame // For stream 0
	outputProtectedQ   []frame // For stream >= 0
	clientInitial      []byte
	recvd              *recvdPackets
	sendFlowControl    flowControl
	recvFlowControl    flowControl
	amountRead         uint64
	sentAcks           map[uint64]ackRanges
	lastInput          time.Time
	idleTimeout        time.Duration
	tpHandler          *transportParametersHandler
	log                loggingFunction
	retransmitTime     time.Duration
	lastSendQueuedTime time.Time
	closingEnd         time.Time
	closePacket        []byte
}

// newConnection creates a new QUIC connection.
func newConnection(tf TransportFactory, remoteAddr *net.UDPAddr, role Role, tls *TlsConfig, handler ConnectionHandler) *Connection {
	transport, err := tf.MakeTransport(remoteAddr)
	if err != nil {
		return nil
	}
	p := &path{
		localConnectionId:  nil,
		remoteConnectionId: nil,
		transport:          transport,
		congestion:         &CongestionControllerDummy{},
		//congestion: newCongestionControllerIetf(c),
	}
	c := &Connection{
		handler:            handler,
		role:               role,
		state:              StateInit,
		version:            kQuicVersion,
		currentPath:        p,
		paths:              map[string]*path{remoteAddr.String(): p},
		transportFactory:   tf,
		tls:                newTlsConn(tls, role),
		writeClear:         nil,
		readClear:          nil,
		writeProtected:     nil,
		readProtected:      nil,
		nextSendPacket:     uint64(0),
		mtu:                kInitialMTU,
		stream0:            nil,
		localBidiStreams:   newStreamSet(streamTypeBidirectionalLocal, role, 1),
		remoteBidiStreams:  newStreamSet(streamTypeBidirectionalRemote, role, kConcurrentStreamsBidi),
		localUniStreams:    newStreamSet(streamTypeUnidirectionalLocal, role, 0),
		remoteUniStreams:   newStreamSet(streamTypeUnidirectionalRemote, role, kConcurrentStreamsUni),
		outputClearQ:       nil,
		outputProtectedQ:   nil,
		clientInitial:      nil,
		recvd:              nil,
		sendFlowControl:    flowControl{0, 0},
		recvFlowControl:    flowControl{kInitialMaxData, 0},
		amountRead:         0,
		sentAcks:           make(map[uint64]ackRanges, 0),
		lastInput:          time.Now(),
		idleTimeout:        time.Second * 5, // a pretty short time
		tpHandler:          nil,
		log:                nil,
		retransmitTime:     kDefaultInitialRtt,
		lastSendQueuedTime: time.Now(),
		closingEnd:         time.Time{}, // Zero time
		closePacket:        nil,
	}

	c.log = newConnectionLogger(c)

	p.congestion.setLostPacketHandler(c.handleLostPacket)

	// TODO(ekr@rtfm.com): This isn't generic, but rather tied to
	// Mint.
	c.tpHandler = newTransportParametersHandler(c.log, role, kQuicVersion)
	c.tls.setTransportParametersHandler(c.tpHandler)

	c.recvd = newRecvdPackets(c.log)

	var clientStreams *streamSet
	if role == RoleClient {
		p.remoteConnectionId, err = c.randomConnectionId(8)
		if err != nil {
			return nil
		}
		p.localConnectionId, err = c.randomConnectionId(kCidDefaultLength)
		if err != nil {
			return nil
		}
		err = c.setupAeadMasking(p.remoteConnectionId)
		if err != nil {
			return nil
		}
		clientStreams = c.localBidiStreams
	} else {
		p.localConnectionId, err = c.randomConnectionId(kCidDefaultLength)
		if err != nil {
			return nil
		}
		c.setState(StateWaitClientInitial)
		clientStreams = c.remoteBidiStreams
	}
	c.stream0 = newStream(c, 0, ^uint64(0), ^uint64(0)).(*stream)
	clientStreams.streams = append(clientStreams.streams, c.stream0)

	err = c.randomPacketNumber()
	if err != nil {
		return nil
	}

	return c
}

// NewConnection makes a new client connection.
func NewConnection(tf TransportFactory, remoteAddr *net.UDPAddr, tls *TlsConfig, handler ConnectionHandler) *Connection {
	return newConnection(tf, remoteAddr, RoleClient, tls, handler)
}

func newServerConnection(tf TransportFactory, remoteAddr *net.UDPAddr, tls *TlsConfig) *Connection {
	return newConnection(tf, remoteAddr, RoleServer, tls, nil)
}

func (c *Connection) String() string {
	return fmt.Sprintf("Conn: %v: %s", c.currentPath, c.role)
}

func (c *Connection) zeroRttAllowed() bool {
	// Placeholder
	return false
}

func (c *Connection) start() error {
	return nil
}

func (c *Connection) Role() Role {
	return c.role
}

func (r Role) String() string {
	switch r {
	case RoleClient:
		return "client"
	case RoleServer:
		return "server"
	default:
		panic("invalid role")
	}
}

func (c *Connection) setState(state State) {
	if c.state == state {
		return
	}

	c.log(logTypeConnection, "Connection state %v -> %v", c.state, state)
	if c.handler != nil {
		c.handler.StateChanged(state)
	}
	c.state = state
}

func (state State) String() string {
	// TODO(ekr@rtfm.com): is there a way to get the name from the
	// const value.
	switch state {
	case StateInit:
		return "StateInit"
	case StateWaitClientInitial:
		return "StateWaitClientInitial"
	case StateWaitServerFirstFlight:
		return "StateWaitServerFirstFlight"
	case StateWaitClientSecondFlight:
		return "StateWaitClientSecondFlight"
	case StateEstablished:
		return "StateEstablished"
	case StateClosing:
		return "StateClosing"
	case StateClosed:
		return "StateClosed"
	case StateError:
		return "StateError"
	default:
		return "Unknown state"
	}
}

// ClientId returns the current identity, as dictated by the client.
func (c *Connection) ClientId() ConnectionId {
	if c.role == RoleClient {
		return c.currentPath.localConnectionId
	}
	return c.currentPath.remoteConnectionId
}

// ServerId returns the current identity, as dictated by the server.
func (c *Connection) ServerId() ConnectionId {
	if c.role == RoleServer {
		return c.currentPath.localConnectionId
	}
	return c.currentPath.remoteConnectionId
}

func (c *Connection) ensureRemoteBidi(id uint64) hasIdentity {
	return c.remoteBidiStreams.ensure(id, func(x uint64) hasIdentity {
		msd := uint64(c.tpHandler.peerParams.maxStreamsData)
		return newStream(c, x, kInitialMaxStreamData, msd)
	}, func(s hasIdentity) {
		if c.handler != nil {
			c.log(logTypeStream, "Created Stream %v", s.Id())
			c.handler.NewStream(s.(Stream))
		}
	})
}

// This manages the creation of local and remote bidirectional streams as well
// as remote unidirectional streams.
func (c *Connection) ensureSendStream(id uint64) sendStreamPrivate {
	var s hasIdentity
	switch streamTypeFromId(id, c.role) {
	case streamTypeBidirectionalLocal:
		s = c.localBidiStreams.get(id)
	case streamTypeBidirectionalRemote:
		s = c.ensureRemoteBidi(id)
	case streamTypeUnidirectionalLocal:
		s = c.localUniStreams.get(id)
	default:
		// Local unidirectional streams can't receive.
		return nil
	}
	if s == nil {
		return nil
	}
	return s.(sendStreamPrivate)
}

// This manages the creation of local and remote bidirectional streams as well
// as remote unidirectional streams.
func (c *Connection) ensureRecvStream(id uint64) recvStreamPrivate {
	var s hasIdentity
	switch streamTypeFromId(id, c.role) {
	case streamTypeBidirectionalLocal:
		s = c.localBidiStreams.get(id)
	case streamTypeBidirectionalRemote:
		s = c.ensureRemoteBidi(id)
	case streamTypeUnidirectionalRemote:
		s = c.remoteUniStreams.ensure(id, func(x uint64) hasIdentity {
			return newRecvStream(c, x, kInitialMaxStreamData)
		}, func(s hasIdentity) {
			if c.handler != nil {
				c.log(logTypeStream, "Created RecvStream %v", s.Id())
				c.handler.NewRecvStream(s.(RecvStream))
			}
		})
	default:
		// Local unidirectional streams can't receive.
		return nil
	}
	if s == nil {
		return nil
	}
	return s.(recvStreamPrivate)
}

func (c *Connection) forEachSend(f func(sendStreamPrivate)) {
	c.localBidiStreams.forEach(func(s hasIdentity) {
		f(s.(sendStreamPrivate))
	})
	c.remoteBidiStreams.forEach(func(s hasIdentity) {
		f(s.(sendStreamPrivate))
	})
	c.localUniStreams.forEach(func(s hasIdentity) {
		f(s.(sendStreamPrivate))
	})
}

func (c *Connection) forEachRecv(f func(recvStreamPrivate)) {
	c.localBidiStreams.forEach(func(s hasIdentity) {
		f(s.(recvStreamPrivate))
	})
	c.remoteBidiStreams.forEach(func(s hasIdentity) {
		f(s.(recvStreamPrivate))
	})
	c.remoteUniStreams.forEach(func(s hasIdentity) {
		f(s.(recvStreamPrivate))
	})
}

func (c *Connection) sendClientInitial() error {
	queued := make([]frame, 0)
	var err error

	c.log(logTypeHandshake, "Sending client initial packet")
	if c.clientInitial == nil {
		c.clientInitial, err = c.tls.handshake(nil)
		if err != nil {
			return err
		}
	}

	f := newStreamFrame(0, 0, c.clientInitial, false)
	// Encode this so we know how much room it is going to take up.
	l, err := f.length()
	if err != nil {
		return err
	}

	/*
	   unless the client has a reasonable assurance that the PMTU is larger.
	   Sending a packet of this size ensures that the network path supports
	   an MTU of this size and helps reduce the amplitude of amplification
	   attacks caused by server responses toward an unverified client
	   address.
	*/
	overhead := c.packetOverhead(c.currentPath, packetTypeInitial)
	topad := kMinimumClientInitialLength - (l + overhead)
	c.log(logTypeHandshake, "Padding with %d padding frames", topad)

	// Enqueue the frame for transmission.
	queued = append(queued, f)

	c.stream0.sendStreamPrivate.(*sendStream).fc.used = uint64(len(c.clientInitial))

	for i := 0; i < topad; i++ {
		queued = append(queued, newPaddingFrame(0))
	}

	c.setState(StateWaitServerFirstFlight)

	_, err = c.sendPacket(packetTypeInitial, queued, nil, false)
	return err
}

func (c *Connection) determineAead(pt packetType) cipher.AEAD {
	var aead cipher.AEAD
	if c.writeProtected != nil {
		aead = c.writeProtected.aead
	}

	if c.role == RoleClient {
		switch {
		case pt == packetTypeInitial:
			aead = c.writeClear.aead
		case pt == packetTypeHandshake:
			aead = c.writeClear.aead
		case pt == packetType0RTTProtected:
			aead = nil // This will cause a crash b/c 0-RTT doesn't work yet
		}
	} else {
		if pt == packetTypeHandshake || pt == packetTypeRetry {
			aead = c.writeClear.aead
		}
	}

	return aead
}

func (c *Connection) sendPacketRaw(pt packetType, version VersionNumber, pn uint64, payload []byte, p *path, containsOnlyAcks bool) ([]byte, error) {
	c.log(logTypeConnection, "Sending packet PT=%v PN=%x: %s", pt, pn, dumpPacket(payload))
	left := c.mtu // track how much space is left for payload

	aead := c.determineAead(pt)
	left -= aead.Overhead()

	packet := newPacket(pt, c.currentPath.remoteConnectionId,
		c.currentPath.localConnectionId, version, pn, payload)
	c.logPacket("Sending", &packet.packetHeader, pn, payload)

	// Encode the header so we know how long it is.
	// TODO(ekr@rtfm.com): this is gross.
	hdr, err := encode(&packet.packetHeader)
	if err != nil {
		return nil, err
	}
	left -= len(hdr)
	assert(left >= len(payload))

	packet.payload = payload
	protected := aead.Seal(nil, c.packetNonce(packet.PacketNumber), packet.payload, hdr)
	b := append(hdr, protected...)

	c.log(logTypeTrace, "Sending packet len=%d, len=%v", len(b), hex.EncodeToString(b))

	if p == nil {
		p = c.currentPath
	}
	p.Send(pn, b, containsOnlyAcks)
	return b, nil
}

// Send a packet with whatever PT seems appropriate now.
func (c *Connection) sendPacketNow(tosend []frame, containsOnlyAcks bool) ([]byte, error) {
	return c.sendPacket(packetTypeProtectedShort, tosend, nil, containsOnlyAcks)
}

// Send a packet with a specific PT.
func (c *Connection) sendPacket(pt packetType, tosend []frame, p *path, containsOnlyAcks bool) ([]byte, error) {
	sent := 0

	payload := make([]byte, 0)

	for _, f := range tosend {
		_, err := f.length()
		if err != nil {
			return nil, err
		}

		c.log(logTypeTrace, "Frame=%v", hex.EncodeToString(f.encoded))

		payload = append(payload, f.encoded...)
		sent++
	}

	pn := c.nextSendPacket
	c.nextSendPacket++

	return c.sendPacketRaw(pt, c.version, pn, payload, p, containsOnlyAcks)
}

// sendOnStream0 is used prior to the handshake completing.  Stream 0 is exempt
// from flow control during the handshake, so this method updates the flow
// control for the stream to ensure that writes always succeed.  The limit is
// reset after writing, which means that flow control for stream 0 can have the
// amount sent (used) higher than the limit (max).  Don't use this method after
// the handshake completes (i.e., for sending NewSessionTicket).
func (c *Connection) sendOnStream0(data []byte) error {
	c.log(logTypeConnection, "sending %v bytes on stream 0", len(data))
	fc := c.sendFlowControl
	c.sendFlowControl.max += uint64(len(data))
	_, err := c.stream0.Write(data)
	c.sendFlowControl = fc
	assert(err != ErrorWouldBlock)
	return err
}

func (c *Connection) makeAckFrame(acks ackRanges, left int) (*frame, int, error) {
	c.log(logTypeConnection, "Making ack frame, room=%d", left)
	af, rangesSent, err := newAckFrame(c.recvd, acks, left)
	if err != nil {
		c.log(logTypeConnection, "Couldn't prepare ACK frame %v", err)
		return nil, 0, err
	}

	return af, rangesSent, nil
}

func (c *Connection) sendQueued(bareAcks bool) (int, error) {
	c.log(logTypeConnection, "Calling sendQueued")

	c.lastSendQueuedTime = time.Now()

	if c.state == StateInit || c.state == StateWaitClientInitial {
		return 0, nil
	}

	sent := int(0)

	/*
	 * ENQUEUE STUFF
	 */

	// FIRST enqueue data for stream 0
	err := c.queueStreamFrames(false)
	if err != nil {
		return sent, err
	}

	// SECOND enqueue data for protected streams
	if c.state == StateEstablished {
		err := c.queueStreamFrames(true)
		if err != nil {
			return sent, err
		}

		/*
		 * SEND STUFF
		 */

		// THIRD send enqueued data from protected streams
		s, err := c.sendQueuedFrames(packetTypeProtectedShort, true, bareAcks)
		if err != nil {
			return sent, err
		}
		sent += s
		// We still want to send out data in unprotected mode but we don't need to just ACK stuff.
		bareAcks = false
	}

	// FOURTH send enqueued data from stream 0
	s, err := c.sendQueuedFrames(packetTypeHandshake, false, bareAcks)
	if err != nil {
		return sent, err
	}
	sent += s

	return sent, nil
}

// Send a packet of stream frames, plus whatever acks fit.
func (c *Connection) sendCombinedPacket(pt packetType, frames []frame, acks ackRanges, left int) (int, error) {
	asent := int(0)
	var err error

	containsOnlyAcks := len(frames) == 0

	if len(acks) > 0 && (left-kMaxAckHeaderLength) >= 0 {
		var af *frame
		af, asent, err = c.makeAckFrame(acks, left)
		if err != nil {
			return 0, err
		}
		if af != nil {
			frames = append(frames, *af)
		}
	}
	// Record which packets we sent ACKs in.
	c.sentAcks[c.nextSendPacket] = acks[0:asent]

	_, err = c.sendPacket(pt, frames, nil, containsOnlyAcks)
	if err != nil {
		return 0, err
	}

	return asent, nil
}

func (c *Connection) queueFrame(q *[]frame, f frame) {
	*q = append(*q, f)
}

func (c *Connection) enqueueStreamFrames(s sendStreamPrivate, q *[]frame) {
	if s == nil {
		return
	}
	for _, ch := range s.outputWritable() {
		f := newStreamFrame(s.Id(), ch.offset, ch.data, ch.last)
		c.queueFrame(q, f)
	}
}

// Send all the queued data on a set of streams with packet type |pt|
func (c *Connection) queueStreamFrames(protected bool) error {
	c.log(logTypeConnection, "%v: queueStreamFrames, protected=%v",
		c.role, protected)

	if !protected {
		c.enqueueStreamFrames(c.stream0, &c.outputClearQ)
		return nil
	}

	// Output all the stream frames that are now permitted by stream flow control
	c.forEachSend(func(s sendStreamPrivate) {
		if s.Id() != 0 {
			c.enqueueStreamFrames(s, &c.outputProtectedQ)
		}
	})
	return nil
}

func (c *Connection) sendFrame(f frame) error {
	if c.state != StateEstablished {
		return ErrorWouldBlock
	}
	c.queueFrame(&c.outputProtectedQ, f)
	_, err := c.sendQueued(false)
	return err
}

func (c *Connection) packetOverhead(p *path, pt packetType) int {
	overhead := c.determineAead(pt).Overhead()
	if pt.isLongHeader() {
		overhead += kLongHeaderLength
		overhead += len(p.localConnectionId)
	} else {
		overhead += 5
	}
	return overhead + len(p.remoteConnectionId)
}

/* Transmit all the frames permitted by connection level flow control and
* the congestion controller. We're going to need to be more sophisticated
* when we actually do connection level flow control. */
func (c *Connection) sendQueuedFrames(pt packetType, protected bool, bareAcks bool) (int, error) {
	c.log(logTypeConnection, "sendQueuedFrames, pt=%v, protected=%v", pt, protected)

	acks := c.recvd.prepareAckRange(protected, false)
	now := time.Now()
	txAge := c.retransmitTime * time.Millisecond
	sent := int(0)
	spaceInCongestionWindow := c.currentPath.congestion.bytesAllowedToSend()

	// Select the queue we will send from
	var queue *[]frame
	if protected {
		queue = &c.outputProtectedQ
	} else {
		queue = &c.outputClearQ
	}

	// TODO(ekr@rtfm.com): Don't retransmit non-retransmittable.

	/* Iterate through the queue, and append frames to packet, sending
	 * packets when the maximum packet size is reached, or we are not
	 * allowed to send more from the congestion controller */

	// Store frames that will be sent in the next packet
	frames := make([]frame, 0)
	// Calculate available space in the next packet.
	overhead := c.packetOverhead(c.currentPath, pt)
	spaceInPacket := c.mtu - overhead
	spaceInCongestionWindow -= overhead

	for i := range *queue {
		f := &((*queue)[i])
		// c.log(logTypeStream, "Examining frame=%v", f)

		frameLength, err := f.length()
		if err != nil {
			return 0, err
		}

		cAge := now.Sub(f.time)
		if f.needsTransmit {
			c.log(logTypeStream, "Frame %v requires transmission", f)
		} else if cAge < txAge {
			c.log(logTypeStream, "Skipping frame %v because sent too recently", f)
			continue
		}

		// if there is no more space in the congestion window, stop
		// trying to send stuff
		if spaceInCongestionWindow < frameLength {
			break
		}

		c.log(logTypeStream, "Sending frame %v, age = %v", f, cAge)
		f.time = now
		f.needsTransmit = false

		// if there is no more space for the next frame in the packet,
		// send it and start forming a new packet
		if spaceInPacket < frameLength {
			asent, err := c.sendCombinedPacket(pt, frames, acks, spaceInPacket)
			if err != nil {
				return 0, err
			}
			sent++

			acks = acks[asent:]
			frames = make([]frame, 0)
			spaceInPacket = c.mtu - overhead
			spaceInCongestionWindow -= overhead
		}

		// add the frame to the packet
		frames = append(frames, *f)
		spaceInPacket -= frameLength
		spaceInCongestionWindow -= frameLength
		// Record that we send this chunk in the current packet
		f.pns = append(f.pns, c.nextSendPacket)
	}

	// Send the remainder, plus any ACKs that are left.
	// TODO(piet@devae.re) This might push the outstanding data over the congestion window
	c.log(logTypeConnection, "Remainder to send? sent=%v frames=%v acks=%v bareAcks=%v",
		sent, len(frames), len(acks), bareAcks)
	if len(frames) > 0 || (len(acks) > 0 && bareAcks) {
		// TODO(ekr@rtfm.com): this may skip acks if there isn't
		// room, but hopefully we eventually catch up.
		_, err := c.sendCombinedPacket(pt, frames, acks, spaceInPacket)
		if err != nil {
			return 0, err
		}

		sent++
	} else if len(acks) > 0 {
		c.log(logTypeAck, "Acks to send, but suppressing bare acks")
	}

	return sent, nil
}

func (c *Connection) handleLostPacket(lostPn uint64) {
	queues := [...][]frame{c.outputClearQ, c.outputProtectedQ}
	for _, queue := range queues {
		for _, frame := range queue {
			for _, pn := range frame.pns {
				if pn == lostPn {
					/* If the packet is considered lost, remember that.
					 * Do *not* remove the PN from the list, because
					 * the packet might pop up later anyway, and then
					 * we want to mark this frame as received. */
					frame.lostPns = append(frame.lostPns, lostPn)
				}
				if len(frame.pns) == len(frame.lostPns) {
					/* if we consider all packets that this frame was send in as lost,
					 * we have to retransmit it. */
					frame.needsTransmit = true
					break
				}
			}
		}
	}
}

// Walk through all the streams and see how many bytes are outstanding.
// Right now this is very expensive.

func (c *Connection) outstandingQueuedBytes() (n int) {
	c.forEachSend(func(s sendStreamPrivate) {
		n += s.outstandingQueuedBytes()
	})

	cd := func(frames []frame) int {
		ret := 0
		for _, f := range frames {
			sf, ok := f.f.(*streamFrame)
			if ok {
				ret += len(sf.Data)
			}
		}
		return ret
	}

	n += cd(c.outputClearQ)
	n += cd(c.outputProtectedQ)

	return
}

// Input provides a packet to the connection.
//
// TODO(ekr@rtfm.com): when is error returned?
func (c *Connection) Input(p *UdpPacket) error {
	return c.handleError(c.input(p))
}

func (c *Connection) fireReadable() {
	if c.handler == nil {
		return
	}

	c.forEachRecv(func(s recvStreamPrivate) {
		if s.Id() != 0 && s.clearReadable() {
			c.handler.StreamReadable(s)
		}
	})
}

func (c *Connection) input(packet *UdpPacket) error {
	if c.isClosed() {
		return ErrorConnIsClosed
	}

	if c.state == StateClosing {
		c.log(logTypeConnection, "Discarding packet while closing (closePacket=%v)", c.closePacket != nil)
		if c.closePacket != nil {
			c.currentPath.transport.Send(c.closePacket)
		}
		return ErrorConnIsClosing
	}

	c.lastInput = time.Now()

	hdr := packetHeader{shortCidLength: kCidDefaultLength}
	p := packet.Data

	c.log(logTypeTrace, "Receiving packet len=%v %v", len(p), hex.EncodeToString(p))
	hdrlen, err := decode(&hdr, p)
	if err != nil {
		c.log(logTypeConnection, "Could not decode packetX: %v", hex.EncodeToString(p))
		return wrapE(ErrorInvalidPacket, err)
	}
	assert(int(hdrlen) <= len(p))

	if hdr.Type.isLongHeader() && hdr.Version != c.version {
		if c.role == RoleServer {
			c.log(logTypeConnection, "Received unsupported version %v, expected %v", hdr.Version, c.version)
			err = c.sendVersionNegotiation(hdr)
			if err != nil {
				return err
			}
			if c.state == StateWaitClientInitial {
				return ErrorDestroyConnection
			}
			return nil
		} else {
			// If we're a client, choke on unknown versions, unless
			// they come in version negotiation packets.
			if hdr.Version != 0 {
				return fmt.Errorf("Received packet with unexpected version %v", hdr.Version)
			}
		}
	}

	typ := hdr.getHeaderType()
	c.log(logTypeTrace, "Received packet %x len=%d", hdr.PacketNumber, len(p))
	c.log(logTypeConnection, "Packet header %v, %d", hdr, typ)

	if hdr.Type.isLongHeader() && hdr.Version == 0 {
		return c.processVersionNegotiation(&hdr, p[hdrlen:])
	}

	if c.state == StateWaitClientInitial {
		if typ != packetTypeInitial {
			c.log(logTypeConnection, "Received unexpected packet before client initial")
			return ErrorDestroyConnection
		}
		err := c.setupAeadMasking(hdr.DestinationConnectionID)
		if err != nil {
			return err
		}
		c.currentPath.localConnectionId, err = c.randomConnectionId(kCidDefaultLength)
		if err != nil {
			return err
		}
		c.currentPath.remoteConnectionId = hdr.SourceConnectionID
	}

	aead := c.readClear.aead
	if hdr.Type.isProtected() {
		if c.readProtected == nil {
			c.log(logTypeConnection, "Received protected data before crypto state is ready")
			return nil
		}
		aead = c.readProtected.aead
	}

	// TODO(ekr@rtfm.com): this dup detection doesn't work right if you
	// get a cleartext packet that has the same PN as a ciphertext or vice versa.
	// Need to fix.
	c.log(logTypeConnection, "Received (unverified) packet with PN=%x PT=%v",
		hdr.PacketNumber, hdr.getHeaderType())

	packetNumber := hdr.PacketNumber
	if c.recvd.initialized() {
		packetNumber = c.expandPacketNumber(hdr.PacketNumber, int(hdr.PacketNumber__length()))
		c.log(logTypeConnection, "Reconstructed packet number %x", packetNumber)
	}

	if c.recvd.initialized() && !c.recvd.packetNotReceived(packetNumber) {
		c.log(logTypeConnection, "Discarding duplicate packet %x", packetNumber)
		return nonFatalError(fmt.Sprintf("Duplicate packet id %x", packetNumber))
	}

	payload, err := aead.Open(nil, c.packetNonce(packetNumber), p[hdrlen:], p[:hdrlen])
	if err != nil {
		c.log(logTypeConnection, "Could not unprotect packet %x", p)
		c.log(logTypeTrace, "Packet %h", p)
		return wrapE(ErrorInvalidPacket, err)
	}

	// Now that we know it's valid, process stateless retry.
	if typ == packetTypeRetry {
		return c.processStatelessRetry(&hdr, payload)
	}

	if !c.recvd.initialized() {
		c.recvd.init(packetNumber)
	}
	// TODO(ekr@rtfm.com): Reject unprotected packets once we are established.

	// We have now verified that this is a valid packet, so mark
	// it received.
	c.logPacket("Received", &hdr, packetNumber, payload)
	probing := false
	ackOnly := true
	switch typ {
	case packetTypeInitial:
		err = c.processClientInitial(&hdr, payload)
	case packetTypeHandshake:
		err = c.processCleartext(&hdr, payload, &ackOnly)
	case packetTypeProtectedShort:
		err = c.processUnprotected(packet, &hdr, packetNumber, payload, &ackOnly, &probing)
	default:
		c.log(logTypeConnection, "Unsupported packet type %v", typ)
		err = internalError("Unsupported packet type %v", typ)
	}
	if err != nil {
		return err
	}
	c.recvd.packetSetReceived(packetNumber, hdr.Type.isProtected(), ackOnly)
	if packetNumber > c.recvd.maxReceived && !probing {
		err = c.migrate(packet.SrcAddr)
		if err != nil {
			return err
		}
	}

	lastSendQueuedTime := c.lastSendQueuedTime

	c.fireReadable()

	// TODO(ekr@rtfm.com): Check for more on stream 0, but we need to properly handle
	// encrypted NST.

	// Check if c.SendQueued() has been called while we were handling
	// the (STREAM) frames. If it has not been called yet, we call it
	// because we might have to ack the current packet, and might
	// have data waiting in the tx queues.
	if lastSendQueuedTime == c.lastSendQueuedTime {
		// Now flush our output buffers.
		_, err = c.sendQueued(true)
		if err != nil {
			return err
		}
	}

	return err
}

func (c *Connection) getOrMakePath(remoteAddr *net.UDPAddr) (*path, error) {
	p := c.paths[remoteAddr.String()]
	if p != nil {
		return p, nil
	}

	c.log(logTypeConnection, "opening new path to %v", remoteAddr)
	t, err := c.transportFactory.MakeTransport(remoteAddr)
	if err != nil {
		return nil, err
	}
	p = &path{
		remoteConnectionId: nil, // TODO: get saved CID
		localConnectionId:  nil, // TODO: get advertised CID and send NEW_CONNECTION_ID
		transport:          t,
		congestion:         &CongestionControllerDummy{},
	}
	// TODO copy RTT information from the current path.
	c.paths[remoteAddr.String()] = p
	return p, nil
}

func (c *Connection) migrate(remoteAddr *net.UDPAddr) error {
	c.log(logTypeConnection, "migrating to %v", remoteAddr)
	p, err := c.getOrMakePath(remoteAddr)
	if err != nil {
		return err
	}
	c.currentPath = p
	return nil
}

func (c *Connection) processClientInitial(hdr *packetHeader, payload []byte) error {
	c.log(logTypeHandshake, "Handling client initial packet")

	// Directly parse the ClientInitial rather than inserting it into
	// the stream processor.
	var sf streamFrame

	// Strip off any initial leading bytes.
	i := int(0)
	var b byte

	for i, b = range payload {
		if b != 0 {
			break
		}
	}
	payload = payload[i:]

	n, err := syntax.Unmarshal(payload, &sf)
	c.log(logTypeHandshake, "Client initial payload=%v", n)

	if err != nil {
		c.log(logTypeConnection, "Failure decoding initial stream frame in ClientInitial")
		return err
	}
	if sf.StreamId != 0 {
		return nonFatalError("Received ClientInitial with stream id %v != 0", sf.StreamId)
	}

	if sf.Offset != 0 {
		return nonFatalError("Received ClientInitial with offset != 0")
	}

	if c.state != StateWaitClientInitial {
		c.log(logTypeConnection, "Received ClientInitial but state = %v", c.GetState())
		return nil
	}

	// TODO(ekr@rtfm.com): check that the length is long enough.
	// TODO(ekr@rtfm.com): check version, etc.
	payload = payload[n:]
	c.log(logTypeTrace, "Expecting %d bytes of padding", len(payload))
	for _, b := range payload {
		if b != 0 {
			return nonFatalError("ClientInitial has non-padding after ClientHello")
		}
	}

	c.logPacket("Received", hdr, hdr.PacketNumber, payload)
	sflt, err := c.tls.handshake(sf.Data)
	if err != nil {
		c.log(logTypeConnection, "TLS connection error: %v", err)
		return err
	}
	c.log(logTypeTrace, "Output of server handshake: %v", hex.EncodeToString(sflt))
	if c.tls.getHsState() == "Server START" {
		c.log(logTypeConnection, "Sending Stateless Retry")
		// We sent HRR
		sf := newStreamFrame(0, 0, sflt, false)
		err := sf.encode()
		if err != nil {
			return err
		}
		_, err = c.sendPacketRaw(packetTypeRetry, kQuicVersion, hdr.PacketNumber, sf.encoded, nil, false)
		return err
	}
	recv0 := c.stream0.recvStreamPrivate.(*recvStream)
	recv0.fc.used = uint64(len(sf.Data))
	recv0.readOffset = uint64(len(sf.Data))
	c.setTransportParameters()

	err = c.sendOnStream0(sflt)
	if err != nil {
		return err
	}

	c.setState(StateWaitClientSecondFlight)

	return err
}

func (c *Connection) processCleartext(hdr *packetHeader, payload []byte, ackOnly *bool) error {
	*ackOnly = true
	c.log(logTypeHandshake, "Reading cleartext in state %v", c.state)
	// TODO(ekr@rtfm.com): Need clearer state checks.
	/*
		We should probably reinstate this once we have encrypted ACKs.

		if c.state != StateWaitServerFirstFlight && c.state != StateWaitClientSecondFlight {
			c.log(logTypeConnection, "Received cleartext packet in inappropriate state. Ignoring")
			return nil
		}*/

	for len(payload) > 0 {
		c.log(logTypeConnection, "payload bytes left %d", len(payload))
		n, f, err := decodeFrame(payload)
		if err != nil {
			c.log(logTypeConnection, "Couldn't decode frame %v", err)
			return wrapE(ErrorInvalidPacket, err)
		}
		c.log(logTypeHandshake, "Frame type %v", f.f.getType())

		payload = payload[n:]
		isAckFrame := false
		switch inner := f.f.(type) {
		case *paddingFrame:
			// Skip.

		case *maxStreamDataFrame:
			if inner.StreamId != 0 {
				return ErrorProtocolViolation
			}
			c.stream0.processMaxStreamData(inner.MaximumStreamData)

		case *streamFrame:
			// If this is duplicate data and if so early abort.
			if inner.Offset+uint64(len(inner.Data)) <= c.stream0.recvStreamPrivate.(*recvStream).readOffset {
				continue
			}

			// This is fresh data so sanity check.
			if c.role == RoleClient {
				if c.state != StateWaitServerFirstFlight {
					// TODO(ekr@rtfm.com): Not clear what to do here. It's
					// clearly a protocol error, but also allows on-path
					// connection termination, so ust ignore the rest of the
					// packet.
					c.log(logTypeConnection, "Received server Handshake after handshake finished")
					return nil
				}
				// This is the first packet from the server, so.
				//
				// 1. Remove the clientInitial packet.
				// 2. Set the outgoing stream offset accordingly
				if len(c.clientInitial) > 0 {
					c.stream0.sendStreamPrivate.(*sendStream).fc.used = uint64(len(c.clientInitial))
					c.clientInitial = nil
				}
				// Set the server's connection ID now.
				// TODO: don't let the server change its mind.  This is complicated
				// because each flight is multiple packets, and Handshake and Retry
				// packets can each set a different value.
				c.currentPath.remoteConnectionId = hdr.SourceConnectionID
			} else {
				if c.state != StateWaitClientSecondFlight {
					// TODO(ekr@rtfm.com): Not clear what to do here. It's
					// clearly a protocol error, but also allows on-path
					// connection termination, so ust ignore the rest of the
					// packet.
					c.log(logTypeConnection, "Received client Handshake after handshake finished")
					return nil
				}
			}

			if inner.StreamId != 0 {
				return nonFatalError("Received cleartext with stream id != 0")
			}

			// Use fake flow control for the handshake.
			fc := flowControl{^uint64(0), 0}
			err = c.stream0.newFrameData(inner.Offset, inner.hasFin(), inner.Data, &fc)
			if err != nil {
				return err
			}
			available, err := ioutil.ReadAll(c.stream0)
			if err != nil && err != ErrorWouldBlock {
				return err
			}
			out, err := c.tls.handshake(available)
			if err != nil {
				return err
			}

			if c.tls.finished {
				err = c.handshakeComplete()
				if err != nil {
					return err
				}
				if c.role == RoleClient {
					// We did this on the server already.
					c.setTransportParameters()
				}
			}

			if len(out) > 0 {
				c.sendOnStream0(out)
				if err != nil {
					return err
				}
				assert(c.tls.finished)
			}

		case *ackFrame:
			//			c.log(logTypeAck, "Received ACK, first range=%x-%x", inner.LargestAcknowledged-inner.AckBlockLength, inner.LargestAcknowledged)

			err = c.processAckFrame(inner, false)
			if err != nil {
				return err
			}
			isAckFrame = true

		case *connectionCloseFrame:
			c.log(logTypeConnection, "Received frame close")
			c.setState(StateClosed)
			return fatalError("Connection closed")

		case *pathChallengeFrame:
			// During the handshake, just put PATH_RESPONSE on the same queue as
			// all other packets.  Assume that our address hasn't changed.
			c.log(logTypeConnection, "Received path challenge")
			c.queueFrame(&c.outputClearQ, newPathResponseFrame(inner.Data[:]))

		case *pathResponseFrame:
			return fatalError("we never send a PATH_CHALLENGE")

		default:
			c.log(logTypeConnection, "Received unexpected frame type")
			return fatalError("Unexpected frame type: %v", f.f.getType())
		}
		if !isAckFrame {
			*ackOnly = false
		}
	}

	return nil
}

func (c *Connection) sendVersionNegotiation(hdr packetHeader) error {
	vn := newVersionNegotiationPacket([]VersionNumber{
		c.version,
		kQuicGreaseVersion1,
	})
	payload, err := encode(vn)
	if err != nil {
		return err
	}
	if hdr.PayloadLength < uint64(len(payload)) {
		// The received packet was far to small to be considered valid.
		// Just drop it without sending anything.
		return nil
	}

	// Generate a random packet type.
	pt := []byte{0}
	_, err = rand.Read(pt)
	if err != nil {
		return err
	}

	c.log(logTypeConnection, "Sending version negotiation packet")
	p := newPacket(packetType(pt[0]&0x7f), hdr.SourceConnectionID, hdr.DestinationConnectionID,
		0, hdr.PacketNumber, payload)

	header, err := encode(&p.packetHeader)
	if err != nil {
		return err
	}
	packet := append(header, payload...)
	// Note that we do not update the congestion controller for this packet.
	// This connection is about to disappear anyway.  Our defense against being
	// used as an amplifier is the size check above.
	c.currentPath.transport.Send(packet)
	return nil
}

func (c *Connection) processVersionNegotiation(hdr *packetHeader, payload []byte) error {
	c.log(logTypeConnection, "Processing version negotiation packet")
	if c.recvd.initialized() {
		c.log(logTypeConnection, "Ignoring version negotiation after received another packet")
	}

	// TODO(ekr@rtfm.com): Check the version negotiation fields.
	// TODO(ekr@rtfm.com): Ignore version negotiation after receiving
	// a non-version-negotiation packet.
	rdr := bytes.NewReader(payload)

	for rdr.Len() > 0 {
		u, err := uintDecodeInt(rdr, 4)
		if err != nil {
			return err
		}
		// Ignore the version we are already speaking.
		if VersionNumber(u) == c.version {
			return nil
		}
	}

	return ErrorReceivedVersionNegotiation
}

// I assume here that Stateless Retry contains just a single stream frame,
// contra the spec but per https://github.com/quicwg/base-drafts/pull/817
func (c *Connection) processStatelessRetry(hdr *packetHeader, payload []byte) error {
	c.log(logTypeConnection, "Processing stateless retry packet %s", dumpPacket(payload))
	if c.recvd.initialized() {
		c.log(logTypeConnection, "Ignoring stateless retry after received another packet")
	}

	// Directly parse the Stateless Retry rather than inserting it into
	// the stream processor.
	var sf streamFrame

	n, err := syntax.Unmarshal(payload, &sf)
	if err != nil {
		c.log(logTypeConnection, "Failure decoding stream frame in Stateless Retry")
		return err
	}

	if int(n) != len(payload) {
		return nonFatalError("Extra stuff in Stateless Retry: (%d != %d) %v", n, len(payload), hex.EncodeToString(payload[n:]))
	}

	if sf.StreamId != 0 {
		return nonFatalError("Received ClientInitial with stream id != 0")
	}

	if sf.Offset != 0 {
		return nonFatalError("Received ClientInitial with offset != 0")
	}

	// TODO(ekr@rtfm.com): add some more state checks that we don't get
	// multiple SRs
	assert(c.tls.getHsState() == "Client WAIT_SH")

	// Pass this data to the TLS connection, which gets us another CH which
	// we insert in ClientInitial
	cflt, err := c.tls.handshake(sf.Data)
	if err != nil {
		c.log(logTypeConnection, "TLS connection error: %v", err)
		return err
	}
	c.log(logTypeTrace, "Output of client handshake: %v", hex.EncodeToString(cflt))

	c.clientInitial = cflt
	return c.sendClientInitial()
}

type frameFilterFunc func(*frame) bool

func filterFrames(in []frame, f frameFilterFunc) []frame {
	out := make([]frame, 0, len(in))
	for _, t := range in {
		if f(&t) {
			out = append(out, t)
		}
	}

	return out
}

func (c *Connection) issueCredit(force bool) {
	c.log(logTypeFlowControl, "connection flow control credit %v", &c.recvFlowControl)
	// Always ensure that there is at least half an initial *stream* flow control window available.
	if !force && c.recvFlowControl.remaining() > (kInitialMaxStreamData/2) {
		return
	}

	c.log(logTypeFlowControl, "connection flow control credit %v", &c.recvFlowControl)
	c.recvFlowControl.max = c.amountRead + kInitialMaxData
	c.outputProtectedQ = filterFrames(c.outputProtectedQ, func(f *frame) bool {
		_, ok := f.f.(*maxDataFrame)
		return !ok
	})

	_ = c.sendFrame(newMaxData(c.recvFlowControl.max))
	c.log(logTypeFlowControl, "connection flow control now %v",
		&c.recvFlowControl)
}

func (c *Connection) updateBlocked() {
	c.outputProtectedQ = filterFrames(c.outputProtectedQ, func(f *frame) bool {
		_, ok := f.f.(*blockedFrame)
		return !ok
	})
	if c.sendFlowControl.remaining() > 0 {
		return
	}
	f := newBlockedFrame(c.sendFlowControl.used)
	_ = c.sendFrame(f)
	c.log(logTypeFlowControl, "sending %v", f)
}

func (c *Connection) issueStreamCredit(s RecvStream, max uint64) {
	// Don't issue credit for stream 0 during the handshake.
	if s.Id() == 0 && c.state != StateEstablished {
		return
	}

	// Remove other MAX_STREAM_DATA frames so we don't retransmit them. This violates
	// the current spec, but offline we all agree it's silly. See:
	// https://github.com/quicwg/base-drafts/issues/806
	c.outputProtectedQ = filterFrames(c.outputProtectedQ, func(f *frame) bool {
		inner, ok := f.f.(*maxStreamDataFrame)
		if !ok {
			return true
		}
		return inner.StreamId != s.Id()
	})

	_ = c.sendFrame(newMaxStreamData(s.Id(), max))
	c.log(logTypeFlowControl, "Issuing stream credit for stream %d, now %v", s.Id(), max)
}

func (c *Connection) updateStreamBlocked(s sendStreamPrivate) {
	c.outputProtectedQ = filterFrames(c.outputProtectedQ, func(f *frame) bool {
		inner, ok := f.f.(*streamBlockedFrame)
		if !ok {
			return true
		}
		return inner.StreamId != s.Id()
	})
	fc := s.flowControl()
	if fc.remaining() > 0 {
		return
	}
	f := newStreamBlockedFrame(s.Id(), fc.used)
	_ = c.sendFrame(f)
	c.log(logTypeFlowControl, "sending %v", f)
}

func (c *Connection) issueStreamIdCredit(t streamType) {
	// TODO work out how to issue in more reasonable increments.
	var max uint64
	switch t {
	case streamTypeBidirectionalRemote:
		max = c.remoteBidiStreams.credit(1)
	case streamTypeUnidirectionalRemote:
		max = c.remoteUniStreams.credit(1)
	}
	c.outputProtectedQ = filterFrames(c.outputProtectedQ, func(f *frame) bool {
		_, ok := f.f.(*maxStreamIdFrame)
		return !ok
	})

	_ = c.sendFrame(newMaxStreamId(max))
	c.log(logTypeFlowControl, "Issuing more %v stream ID credit: %d", t, max)
}

// Processes a short header packet contents.
func (c *Connection) processUnprotected(udp *UdpPacket, hdr *packetHeader, packetNumber uint64, payload []byte, ackOnly *bool, probing *bool) error {
	c.log(logTypeHandshake, "Reading unprotected data in state %v", c.state)
	c.log(logTypeConnection, "Received Packet=%v", dumpPacket(payload))

	*ackOnly = true
	*probing = true

	for len(payload) > 0 {
		c.log(logTypeConnection, "payload bytes left %d", len(payload))
		n, f, err := decodeFrame(payload)
		if err != nil {
			c.log(logTypeConnection, "Couldn't decode frame %v", err)
			return err
		}
		c.log(logTypeConnection, "Frame type %v", f.f.getType())

		payload = payload[n:]
		isAckFrame := false
		isProbingFrame := false

		switch inner := f.f.(type) {
		case *paddingFrame:
			isProbingFrame = true
			// Skip.
		case *rstStreamFrame:
			// TODO(ekr@rtfm.com): Don't let the other side initiate
			// streams that are the wrong parity.
			c.log(logTypeStream, "Received RST_STREAM on stream %v", inner.StreamId)
			s := c.ensureRecvStream(inner.StreamId)
			if s == nil {
				return ErrorProtocolViolation
			}

			err = s.handleReset(inner.FinalOffset)
			if err != nil {
				return err
			}
			c.issueStreamIdCredit(streamTypeFromId(inner.StreamId, c.role))

		case *stopSendingFrame:
			c.log(logTypeStream, "Received STOP_SENDING on stream %v", inner.StreamId)
			s := c.ensureSendStream(inner.StreamId)
			if s == nil {
				return ErrorProtocolViolation
			}

			err = s.Reset(kQuicErrorNoError)
			if err != nil {
				return err
			}

		case *connectionCloseFrame:
			c.log(logTypeConnection, "Received CONNECTION_CLOSE")
			// Don't save the packet, we should go straight to draining.
			// Note that we don't bother with the optional transition from draining to
			// closing because we don't bother to decrypt packets that are received while
			// closing.
			c.close(kQuicErrorNoError, "received CONNECTION_CLOSE", false)
			// Stop processing any more frames.
			return nil

		case *maxDataFrame:
			c.sendFlowControl.update(inner.MaximumData)
			c.updateBlocked()

		case *blockedFrame:
			c.log(logTypeFlowControl, "peer is blocked at %v", inner.Offset)
			// We don't strictly have to issue credit here, but receiving
			// BLOCKED is a potential sign that a MAX_DATA frame was lost.
			// It's also potentially a sign that the amount we're crediting is
			// too little, but we aren't tuning this yet.
			// Instead, aggressively send more credit.
			c.issueCredit(true)

		case *maxStreamDataFrame:
			s := c.ensureSendStream(inner.StreamId)
			if s == nil {
				return ErrorProtocolViolation
			}
			s.processMaxStreamData(inner.MaximumStreamData)
			c.updateStreamBlocked(s)

		case *streamBlockedFrame:
			s := c.ensureRecvStream(inner.StreamId)
			if s == nil {
				return ErrorProtocolViolation
			}
			c.log(logTypeFlowControl, "peer stream %d is blocked at %v", s.Id(), inner.Offset)
			// Aggressively send credit.  See the comment on BLOCKED above.
			s.updateMaxStreamData(true)

		case *maxStreamIdFrame:
			switch streamTypeFromId(inner.MaximumStreamId, c.role) {
			case streamTypeBidirectionalLocal:
				c.localBidiStreams.updateMax(inner.MaximumStreamId)
			case streamTypeUnidirectionalLocal:
				c.localUniStreams.updateMax(inner.MaximumStreamId)
			default:
				return ErrorProtocolViolation
			}

		case *ackFrame:
			//			c.log(logTypeConnection, "Received ACK, first range=%v-%v", inner.LargestAcknowledged-inner.AckBlockLength, inner.LargestAcknowledged)
			err = c.processAckFrame(inner, true)
			if err != nil {
				return err
			}
			isAckFrame = true

		case *streamFrame:
			c.log(logTypeStream, "Received on stream %v", inner)
			s := c.ensureRecvStream(inner.StreamId)
			if s == nil {
				return ErrorProtocolViolation
			}

			err = s.newFrameData(inner.Offset, inner.hasFin(), inner.Data, &c.recvFlowControl)
			if err != nil {
				return err
			}

			if inner.StreamId == 0 {
				// TLS process for NST.
				available, err := ioutil.ReadAll(s)
				if err != nil && err != ErrorWouldBlock {
					return err
				}
				err = c.tls.readPostHandshake(available)
				if err != nil {
					return err
				}
			}

		case *pathChallengeFrame:
			// If we receive a PATH_CHALLENGE, the response needs to go back
			// to the same remote address.  That means sending a packet directly.
			c.log(logTypeConnection, "Received path challenge")
			// TODO use new connection ID here
			frames := []frame{newPathResponseFrame(inner.Data[:])}
			p, err := c.getOrMakePath(udp.SrcAddr)
			if err != nil {
				return err
			}
			_, err = c.sendPacket(packetTypeProtectedShort, frames, p, false)
			if err != nil {
				c.log(logTypeConnection, "couldn't send PATH_RESPONSE")
			}

			isProbingFrame = true

		case *pathResponseFrame:
			return fatalError("we never send a PATH_CHALLENGE")

		default:
			c.log(logTypeConnection, "Received unexpected frame type")
		}
		if !isProbingFrame {
			*probing = false
		}
		if !isAckFrame {
			*ackOnly = false
		}
	}

	return nil
}

func (c *Connection) removeAckedFrames(pn uint64, qp *[]frame) {
	q := *qp

	c.log(logTypeStream, "Removing ACKed chunks PN=%x, currently %v chunks", pn, len(q))

	for i := int(0); i < len(q); {
		remove := false
		f := q[i]
		// c.log(logTypeStream, "Examining frame %v PNs=%v", f, f.pns)
		for _, p := range f.pns {
			if pn == p {
				remove = true
				break
			}
		}

		if remove {
			c.log(logTypeStream, "Removing frame %v, sent in PN %v", f.f, pn)
			q = append(q[:i], q[i+1:]...)
		} else {
			i++
		}
	}
	c.log(logTypeStream, "Un-acked chunks remaining %v", len(q))
	*qp = q
}

func (c *Connection) processAckRange(start uint64, end uint64, protected bool) {
	assert(start <= end)
	c.log(logTypeConnection, "Process ACK range %v-%v", start, end)
	pn := start
	// Unusual loop structure to avoid weirdness at 2^64-1
	for {
		// TODO(ekr@rtfm.com): properly filter for ACKed packets which are in the
		// wrong key phase.
		c.log(logTypeConnection, "processing ACK for PN=%x", pn)

		// 1. Go through the outgoing queues and remove all the acked chunks.
		c.removeAckedFrames(pn, &c.outputClearQ)
		if protected {
			c.removeAckedFrames(pn, &c.outputProtectedQ)
		}

		// 2. Mark all the packets that were ACKed in this packet as double-acked.
		acks, ok := c.sentAcks[pn]
		if ok {
			for _, a := range acks {
				c.log(logTypeAck, "Ack2 for ack range last=%v len=%v", a.lastPacket, a.count)

				if a.lastPacket < c.recvd.minNotAcked2 {
					// if there is nothing unacked in the range, continue
					continue
				}

				for i := uint64(0); i < a.count; i++ {
					c.recvd.packetSetAcked2(a.lastPacket - i)
				}
			}
		}
		if pn == end {
			break
		}
		pn++
	}
}

func (c *Connection) processAckFrame(f *ackFrame, protected bool) error {
	var receivedAcks ackRanges
	c.log(logTypeAck, "processing ACK last=%x first ack block=%d", f.LargestAcknowledged, f.FirstAckBlock)
	end := f.LargestAcknowledged

	start := (end - f.FirstAckBlock)

	// Decode ACK Delay
	ackDelayMicros := QuicFloat16(f.AckDelay).Float32()
	ackDelay := time.Duration(ackDelayMicros * 1e3)

	// Process the First ACK Block
	c.log(logTypeAck, "processing ACK range %x-%x", start, end)
	c.processAckRange(start, end, protected)
	receivedAcks = append(receivedAcks, ackRange{end, end - start})

	// TODO(ekr@rtfm.com): Check for underflow.

	// Process aditional ACK Blocks
	last := start

	for _, block := range f.AckBlockSection {
		end = last - uint64(block.Gap) - 2
		start = end - block.Length

		// Not clear why the peer did this, but ignore.
		if block.Length == 0 {
			last -= uint64(block.Gap)
			c.log(logTypeAck, "encountered empty ACK block")
			continue
		}

		last = start
		c.log(logTypeAck, "processing ACK range %x-%x", start, end)
		c.processAckRange(start, end, protected)
		receivedAcks = append(receivedAcks, ackRange{end, end - start})
	}

	for _, p := range c.paths {
		p.congestion.onAckReceived(receivedAcks, ackDelay)
	}

	return nil
}

// Check the connection's timer and process any events whose time has
// expired in the meantime. This includes sending retransmits, etc.
func (c *Connection) CheckTimer() (int, error) {
	if c.isClosed() {
		return 0, ErrorConnIsClosed
	}

	c.log(logTypeConnection, "Checking timer")

	if c.state == StateClosing {
		if time.Now().After(c.closingEnd) {
			c.log(logTypeConnection, "End of draining period, closing")
			c.setState(StateClosed)
			return 0, ErrorConnIsClosed
		}
		return 0, ErrorConnIsClosing
	}

	if time.Now().After(c.lastInput.Add(c.idleTimeout)) {
		c.log(logTypeConnection, "Connection is idle for more than %v", c.idleTimeout)
		c.setState(StateClosing)
		c.closingEnd = time.Now()
		return 0, ErrorConnIsClosing
	}

	// Right now just re-send everything we might need to send.

	// Special case the client's first message.
	if c.role == RoleClient && (c.state == StateInit ||
		c.state == StateWaitServerFirstFlight) {
		err := c.sendClientInitial()
		return 1, err
	}

	n, err := c.sendQueued(false)
	return n, c.handleError(err)
}

func (c *Connection) setTransportParameters() {
	// TODO(ekr@rtfm.com): Process the others..

	// Cut stream 0 flow control down to something reasonable.
	c.stream0.sendStreamPrivate.(*sendStream).fc.max = uint64(c.tpHandler.peerParams.maxStreamsData)

	c.sendFlowControl.update(uint64(c.tpHandler.peerParams.maxData))
	c.localBidiStreams.nstreams = c.tpHandler.peerParams.maxStreamsBidi
	c.localUniStreams.nstreams = c.tpHandler.peerParams.maxStreamsUni
}

func (c *Connection) setupAeadMasking(cid ConnectionId) (err error) {
	params := mint.CipherSuiteParams{
		Suite:  mint.TLS_AES_128_GCM_SHA256,
		Cipher: nil,
		Hash:   crypto.SHA256,
		KeyLen: 16,
		IvLen:  12,
	}

	var sendLabel, recvLabel string
	if c.role == RoleClient {
		sendLabel = clientCtSecretLabel
		recvLabel = serverCtSecretLabel
	} else {
		sendLabel = serverCtSecretLabel
		recvLabel = clientCtSecretLabel
	}
	c.writeClear, err = generateCleartextKeys(cid, sendLabel, &params)
	if err != nil {
		return
	}
	c.readClear, err = generateCleartextKeys(cid, recvLabel, &params)
	if err != nil {
		return
	}

	return nil
}

// Called when the handshake is complete.
func (c *Connection) handshakeComplete() (err error) {
	var sendLabel, recvLabel string
	if c.role == RoleClient {
		sendLabel = clientPpSecretLabel
		recvLabel = serverPpSecretLabel
	} else {
		sendLabel = serverPpSecretLabel
		recvLabel = clientPpSecretLabel
	}

	c.writeProtected, err = newCryptoStateFromTls(c.tls, sendLabel)
	if err != nil {
		return
	}
	c.readProtected, err = newCryptoStateFromTls(c.tls, recvLabel)
	if err != nil {
		return
	}
	c.setState(StateEstablished)

	return nil
}

func (c *Connection) packetNonce(pn uint64) []byte {
	return encodeArgs(pn)
}

// CreateStream creates a stream that can send and receive.
func (c *Connection) CreateStream() Stream {
	c.log(logTypeStream, "Creating new Stream")
	s := c.localBidiStreams.create(func(id uint64) hasIdentity {
		recvMax := uint64(c.tpHandler.peerParams.maxStreamsData)
		return newStream(c, id, kInitialMaxStreamData, recvMax)
	})
	if s != nil {
		c.log(logTypeStream, "Created Stream %v", s.Id())
		return s.(Stream)
	}
	nextStreamId := c.localBidiStreams.id(len(c.localBidiStreams.streams))
	c.sendFrame(newStreamIdBlockedFrame(nextStreamId))
	return nil
}

// CreateSendStream creates a stream that can send only.
func (c *Connection) CreateSendStream() SendStream {
	c.log(logTypeStream, "Creating new SendStream")
	s := c.localUniStreams.create(func(id uint64) hasIdentity {
		recvMax := uint64(c.tpHandler.peerParams.maxStreamsData)
		return newSendStream(c, id, recvMax)
	})
	if s != nil {
		c.log(logTypeStream, "Created SendStream %v", s.Id())
		return s.(SendStream)
	}
	return nil
}

// GetStream retrieves a stream with the given id. Returns nil if
// no such stream exists.
func (c *Connection) GetStream(id uint64) Stream {
	var s hasIdentity
	switch streamTypeFromId(id, c.role) {
	case streamTypeBidirectionalLocal:
		s = c.localBidiStreams.get(id)
	case streamTypeBidirectionalRemote:
		s = c.remoteBidiStreams.get(id)
	default:
		return nil
	}
	if s != nil {
		return s.(Stream)
	}
	return nil
}

// GetSendStream retrieves a stream with the given id. Returns
// nil if no such stream exists.
func (c *Connection) GetSendStream(id uint64) SendStream {
	s := c.localUniStreams.get(id)
	if s != nil {
		return s.(SendStream)
	}
	return nil
}

// GetRecvStream retrieves a stream with the given id. Returns
// nil if no such stream exists.
func (c *Connection) GetRecvStream(id uint64) RecvStream {
	s := c.remoteUniStreams.get(id)
	if s != nil {
		return s.(RecvStream)
	}
	return nil
}

func (c *Connection) randomConnectionId(size int) (ConnectionId, error) {
	assert(size == 0 || (size >= 4 && size <= 18))
	b := make([]byte, size)

	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}

	return ConnectionId(b), nil
}

func (c *Connection) randomPacketNumber() error {
	b := make([]byte, 4)

	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return err
	}

	v := uint64(0)
	for _, c := range b {
		v <<= 8
		v |= uint64(c)
	}
	c.nextSendPacket = v >> 1
	return nil
}

// Set the handler class for a given connection.
func (c *Connection) SetHandler(h ConnectionHandler) {
	c.handler = h
}

func (c *Connection) close(code ErrorCode, reason string, savePacket bool) error {
	if c.isClosed() {
		return nil
	}
	if c.state == StateClosing {
		return nil
	}

	c.closingEnd = time.Now().Add(3 * c.currentPath.congestion.rto())
	c.setState(StateClosing)
	f := newConnectionCloseFrame(code, reason)
	closePacket, err := c.sendPacketNow([]frame{f}, false)
	if err != nil {
		return err
	}
	if savePacket {
		c.closePacket = closePacket
	}
	return nil
}

// Close a connection.
func (c *Connection) Close() error {
	c.log(logTypeConnection, "Close()")
	return c.close(kQuicErrorNoError, "You don't have to go home but you can't stay here", true)
}

func (c *Connection) isDead() bool {
	return c.state == StateError
}

func (c *Connection) isClosed() bool {
	return c.state == StateError || c.state == StateClosed
}

// Get the current state of a connection.
func (c *Connection) GetState() State {
	return c.state
}

func (c *Connection) handleError(e error) error {
	c.log(logTypeConnection, "Handling error: %v", e)
	if e == nil {
		return nil
	}

	if !isFatalError(e) {
		return nil
	}

	// Connection has failed.
	logf(logTypeConnection, "failed with Error=%v", e.Error())
	c.setState(StateError)

	return e
}

func (c *Connection) logPacket(dir string, hdr *packetHeader, pn uint64, payload []byte) {
	l := fmt.Sprintf("Packet %s: PN=%x LEN=%d hdr[%s]: %s", dir, pn, len(payload), hdr.String(), dumpPacket(payload))
	c.log(logTypePacket, l)
	c.log(logTypeConnection, l)
}

// S 5.8:
//   A packet number is decoded by finding the packet number value that is
//   closest to the next expected packet.  The next expected packet is the
//   highest received packet number plus one.  For example, if the highest
//   successfully authenticated packet had a packet number of 0xaa82f30e,
//   then a packet containing a 16-bit value of 0x1f94 will be decoded as
//   0xaa831f94.
//
//
// The expected sequence number is composed of:
//   EHi || ELo
//
// We get |pn|, which is the same length as ELo, so the possible values
// are:
//
// if pn > ELo, then either EHi || pn  or  EHi - 1 || pn  (wrapped downward)
// if Pn == Elo then Ei || pn
// if Pn < Elo  then either EHi || on  or  EHi + 1 || pn  (wrapped upward)
func (c *Connection) expandPacketNumber(pn uint64, size int) uint64 {
	if size == 8 {
		return pn
	}

	expected := c.recvd.maxReceived + 1
	c.log(logTypeTrace, "Expanding packet number, pn=%x size=%d expected=%x", pn, size, expected)

	// Mask off the top of the expected sequence number
	mask := uint64(1)
	mask = (mask << (uint8(size) * 8)) - 1
	expectedLow := mask & expected
	high := ^mask & expected
	match := high | pn

	// Exact match
	if expectedLow == pn {
		return match
	}

	if pn > expectedLow {
		if high == 0 {
			return match
		}
		wrap := (high - 1) | pn
		if (expected - wrap) <= (match - expected) {
			return wrap
		}
		return match
	}

	// expectedLow > pn
	wrap := (high + 1) | pn
	if (expected - match) <= (wrap - expected) {
		return match
	}
	return wrap
}
