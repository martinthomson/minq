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
	"io/ioutil"
	"time"

	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
)

type Role uint8

const (
	RoleClient = Role(1)
	RoleServer = Role(2)
)

// The state of a QUIC connection.
type State uint8

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

type streamType uint8

// These values match the low bits of the stream ID for a client, but the low
// bit is flipped for a server.
const (
	streamTypeBidirectionalLocal   = streamType(0)
	streamTypeBidirectionalRemote  = streamType(1)
	streamTypeUnidirectionalLocal  = streamType(2)
	streamTypeUnidirectionalRemote = streamType(3)
)

const (
	kMinimumClientInitialLength  = 1200 // draft-ietf-quic-transport S 9.0
	kLongHeaderLength            = 17
	kInitialIntegrityCheckLength = 16   // Overhead.
	kInitialMTU                  = 1252 // 1280 - UDP headers.
)

// The protocol version number.
type VersionNumber uint32

const (
	kQuicDraftVersion   = 8
	kQuicVersion        = VersionNumber(0xff000000 | kQuicDraftVersion)
	kQuicGreaseVersion1 = VersionNumber(0x1a1a1a1a)
	kQuicGreaseVersion2 = VersionNumber(0x2a2a2a2a)
)

const (
	kQuicALPNToken = "hq-08"
)

// Interface for the handler object which the Connection will call
// to notify of events on the connection.
type ConnectionHandler interface {
	// The connection has changed state to state |s|
	StateChanged(s State)

	// NewUnidirectionalStream indicates that a new unidirectional stream has been
	// created by the remote peer. |s| contains the stream.
	NewUnidirectionalStream(s RecvStream)

	// NewBidirectionalStream indicates that a new bidirectional stream has been
	// created by the remote peer. |s| contains the stream.
	NewBidirectionalStream(s Stream)

	// StreamReadable indicates that |s| is now readable.
	StreamReadable(s RecvStream)
}

// Internal structures indicating ranges to ACK
type ackRange struct {
	lastPacket uint64 // Packet with highest pn in range
	count      uint64 // Total number of packets in range
}

type ackRanges []ackRange

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
	handler        ConnectionHandler
	role           Role
	state          State
	version        VersionNumber
	clientConnId   ConnectionId
	serverConnId   ConnectionId
	transport      Transport
	tls            *tlsConn
	writeClear     *cryptoState
	readClear      *cryptoState
	writeProtected *cryptoState
	readProtected  *cryptoState
	nextSendPacket uint64
	mtu            int
	// Locally created streams.
	localBidiStreams []Stream
	// The number of local bidirectional streams we are permitted to create (not the max stream ID).
	maxLocalBidi       int
	remoteBidiStreams  []Stream
	maxRemoteBidi      int
	localUniStreams    []SendStream
	maxLocalUni        int
	remoteUniStreams   []RecvStream
	maxRemoteUni       int
	outputClearQ       []frame // For stream 0
	outputProtectedQ   []frame // For stream >= 0
	clientInitial      []byte
	recvd              *recvdPackets
	sentAcks           map[uint64]ackRanges
	lastInput          time.Time
	idleTimeout        uint16
	tpHandler          *transportParametersHandler
	log                loggingFunction
	retransmitTime     time.Duration
	congestion         CongestionController
	lastSendQueuedTime time.Time
	closingEnd         time.Time
	closePacket        []byte
}

// Create a new QUIC connection. Should only be used with role=RoleClient,
// though we use it with RoleServer internally.
func NewConnection(trans Transport, role Role, tls *TlsConfig, handler ConnectionHandler) *Connection {
	c := Connection{
		handler:            handler,
		role:               role,
		state:              StateInit,
		version:            kQuicVersion,
		clientConnId:       0,
		serverConnId:       0,
		transport:          trans,
		tls:                newTlsConn(tls, role),
		writeClear:         nil,
		readClear:          nil,
		writeProtected:     nil,
		readProtected:      nil,
		nextSendPacket:     uint64(0),
		mtu:                kInitialMTU,
		localBidiStreams:   make([]Stream, 1),
		maxLocalBidi:       1,
		remoteBidiStreams:  make([]Stream, 0, kConcurrentStreamsBidi),
		maxRemoteBidi:      kConcurrentStreamsBidi,
		localUniStreams:    make([]SendStream, 0),
		maxLocalUni:        0,
		remoteUniStreams:   make([]RecvStream, 0, kConcurrentStreamsUni),
		maxRemoteUni:       kConcurrentStreamsUni,
		outputClearQ:       nil,
		outputProtectedQ:   nil,
		clientInitial:      nil,
		recvd:              nil,
		sentAcks:           make(map[uint64]ackRanges, 0),
		lastInput:          time.Now(),
		idleTimeout:        10, // Very short idle timeout.
		tpHandler:          nil,
		log:                nil,
		retransmitTime:     kDefaultInitialRtt,
		congestion:         nil,
		lastSendQueuedTime: time.Now(),
		closingEnd:         time.Time{}, // Zero time
		closePacket:        nil,
	}

	c.log = newConnectionLogger(&c)

	//c.congestion = newCongestionControllerIetf(&c)
	c.congestion = &CongestionControllerDummy{}
	c.congestion.setLostPacketHandler(c.handleLostPacket)

	// TODO(ekr@rtfm.com): This isn't generic, but rather tied to
	// Mint.
	c.tpHandler = newTransportParametersHandler(c.log, role, kQuicVersion)
	c.tls.setTransportParametersHandler(c.tpHandler)

	c.recvd = newRecvdPackets(c.log)
	tmp, err := generateRand64()
	if err != nil {
		return nil
	}
	cid := ConnectionId(tmp)
	if role == RoleClient {
		c.clientConnId = cid
		err = c.setupAeadMasking()
		if err != nil {
			return nil
		}
	} else {
		c.serverConnId = cid
		c.setState(StateWaitClientInitial)
	}
	tmp, err = generateRand64()
	if err != nil {
		return nil
	}
	c.nextSendPacket = tmp & 0x7fffffff
	c.localBidiStreams[0] = newStream(&c, 0, ^uint64(0))
	c.maxLocalBidi = 1
	return &c
}

func (c *Connection) zeroRttAllowed() bool {
	// Placeholder
	return false
}

func (c *Connection) start() error {
	return nil
}

func (c *Connection) label() string {
	return string(c.role)
}

func (c *Connection) Role() Role {
	return c.role
}

func (c *Connection) setState(state State) {
	if c.state == state {
		return
	}

	c.log(logTypeConnection, "%s: Connection state %s -> %v", c.label(), StateName(c.state), StateName(state))
	if c.handler != nil {
		c.handler.StateChanged(state)
	}
	c.state = state
}

func StateName(state State) string {
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

func streamTypeFromId(id uint64, role Role) streamType {
	t := id & 3
	if role == RoleServer {
		t ^= 1
	}
	return streamType(t)
}

func (t streamType) suffix(role Role) uint64 {
	suff := uint64(t)
	if role == RoleServer {
		suff ^= 1
	}
	return suff
}

// This makes a bidirectional local stream.
func (c *Connection) ensureLocalBidiStream(id uint64) (Stream, error) {
	c.log(logTypeStream, "Ensuring local bidirectional stream %d exists", id)

	assert(c.tpHandler.peerParams != nil)
	assert(id&3 == streamTypeBidirectionalLocal.suffix(c.role))
	assert((id >> 2) < uint64(^uint(0)>>1)) // safeguard against overflow
	index := int(id >> 2)
	assert(index < c.maxLocalBidi)
	if len(c.localBidiStreams) <= index {
		// TODO(ekr@rtfm.com): this is not really done, because we never clean up
		// Resize to fit.
		needed := index - len(c.localBidiStreams) + 1
		c.localBidiStreams = append(c.localBidiStreams, make([]Stream, needed)...)
	}
	if c.localBidiStreams[index] == nil {
		msd := uint64(c.tpHandler.peerParams.maxStreamsData)
		c.localBidiStreams[index] = newStream(c, id, msd)
	}
	// No notification for local streams
	return c.localBidiStreams[index], nil
}

func (c *Connection) ensureLocalUniStream(id uint64) (SendStream, error) {
	c.log(logTypeStream, "Ensuring local unidirectional stream %d exists", id)

	assert(c.tpHandler.peerParams != nil)
	assert(id&3 == streamTypeUnidirectionalLocal.suffix(c.role))
	assert((id >> 2) < uint64(^uint(0)>>1)) // safeguard against overflow
	index := int(id >> 2)
	assert(index < c.maxLocalUni)
	if len(c.localUniStreams) <= index {
		needed := index - len(c.localUniStreams) + 1
		c.localUniStreams = append(c.localUniStreams, make([]SendStream, needed)...)
	}
	if c.localUniStreams[index] == nil {
		// TODO: separate initial MAX_STREAM_DATA by stream type
		msd := uint64(c.tpHandler.peerParams.maxStreamsData)
		c.localUniStreams[index] = newSendStream(c, id, msd)
	}
	return c.localUniStreams[index], nil
}

func (c *Connection) ensureRemoteBidiStream(id uint64) (Stream, error) {
	c.log(logTypeStream, "Ensuring remote bidirectional stream %d exists", id)

	assert(c.tpHandler.peerParams != nil)
	assert(id&3 == streamTypeBidirectionalRemote.suffix(c.role))
	assert((id >> 2) < uint64(^uint(0)>>1)) // safeguard against overflow
	index := int(id >> 2)
	if index >= c.maxRemoteBidi {
		return nil, ErrorProtocolViolation
	}
	if len(c.remoteBidiStreams) <= index {
		needed := index - len(c.remoteBidiStreams) + 1
		c.remoteBidiStreams = append(c.remoteBidiStreams, make([]Stream, needed)...)
	}
	if c.remoteBidiStreams[index] == nil {
		msd := uint64(c.tpHandler.peerParams.maxStreamsData)
		c.remoteBidiStreams[index] = newStream(c, id, msd)
		if c.handler != nil {
			c.handler.NewBidirectionalStream(c.remoteBidiStreams[index])
		}
	}
	return c.remoteBidiStreams[index], nil
}

func (c *Connection) ensureRemoteUniStream(id uint64) (RecvStream, error) {
	c.log(logTypeStream, "Ensuring remote unidirectional stream %d exists", id)

	assert(c.tpHandler.peerParams != nil)
	assert(id&3 == streamTypeUnidirectionalRemote.suffix(c.role))
	assert((id >> 2) < uint64(^uint(0)>>1)) // safeguard against overflow
	index := int(id >> 2)
	if index >= c.maxRemoteUni {
		return nil, ErrorProtocolViolation
	}
	if len(c.remoteUniStreams) <= index {
		needed := index - len(c.remoteUniStreams) + 1
		c.remoteUniStreams = append(c.remoteUniStreams, make([]RecvStream, needed)...)
	}
	if c.remoteUniStreams[index] == nil {
		c.remoteUniStreams[index] = newRecvStream(c, id)
		if c.handler != nil {
			c.handler.NewUnidirectionalStream(c.remoteUniStreams[index])
		}
	}
	return c.remoteUniStreams[index], nil
}

// This manages the creation of local and remote bidirectional streams as well
// as remote unidirectional streams.
func (c *Connection) ensureSendStream(id uint64) (SendStream, error) {
	switch streamTypeFromId(id, c.role) {
	case streamTypeBidirectionalLocal:
		return c.ensureLocalBidiStream(id)
	case streamTypeBidirectionalRemote:
		return c.ensureRemoteBidiStream(id)
	case streamTypeUnidirectionalLocal:
		return c.ensureLocalUniStream(id)
	default:
		// Local unidirectional streams can't receive.
		return nil, ErrorProtocolViolation
	}
}

// This manages the creation of local and remote bidirectional streams as well
// as remote unidirectional streams.
func (c *Connection) ensureRecvStream(id uint64) (RecvStream, error) {
	switch streamTypeFromId(id, c.role) {
	case streamTypeBidirectionalLocal:
		return c.ensureLocalBidiStream(id)
	case streamTypeBidirectionalRemote:
		return c.ensureRemoteBidiStream(id)
	case streamTypeUnidirectionalRemote:
		return c.ensureRemoteUniStream(id)
	default:
		// Local unidirectional streams can't receive.
		return nil, ErrorProtocolViolation
	}
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
	topad := kMinimumClientInitialLength - (kLongHeaderLength + l + kInitialIntegrityCheckLength)
	c.log(logTypeHandshake, "Padding with %d padding frames", topad)

	// Enqueue the frame for transmission.
	queued = append(queued, f)

	stream0 := c.localBidiStreams[0].(*stream)
	stream0.sendStreamBase.offset = uint64(len(c.clientInitial))

	for i := 0; i < topad; i++ {
		queued = append(queued, newPaddingFrame(0))
	}

	c.setState(StateWaitServerFirstFlight)

	_, err = c.sendPacket(packetTypeInitial, queued, false)
	return err
}

func (c *Connection) sendSpecialClearPacket(pt uint8, connId ConnectionId, pn uint64, version VersionNumber, payload []byte) error {
	c.log(logTypeConnection, "Sending special clear packet type=%v", pt)
	p := packet{
		packetHeader{
			pt | packetFlagLongHeader,
			connId,
			version,
			pn,
		},
		payload,
	}

	packet, err := encode(&p.packetHeader)
	if err != nil {
		return err
	}
	packet = append(packet, payload...)
	c.congestion.onPacketSent(pn, false, len(packet)) //TODO(piet@devae.re) check isackonly
	c.transport.Send(packet)
	return nil
}

func (c *Connection) determineAead(pt uint8) cipher.AEAD {
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

func (c *Connection) sendPacketRaw(pt uint8, connId ConnectionId, pn uint64, version VersionNumber, payload []byte, containsOnlyAcks bool) ([]byte, error) {
	c.log(logTypeConnection, "Sending packet PT=%v PN=%x: %s", pt, c.nextSendPacket, dumpPacket(payload))
	left := c.mtu // track how much space is left for payload

	aead := c.determineAead(pt)
	left -= aead.Overhead()

	if pt == packetTypeProtectedShort {
		pt = 0x1d
	} else {
		pt = pt | packetFlagLongHeader
	}
	p := packet{
		packetHeader{
			pt,
			connId,
			version,
			pn,
		},
		nil,
	}
	c.logPacket("Sent", &p.packetHeader, pn, payload)

	// Encode the header so we know how long it is.
	// TODO(ekr@rtfm.com): this is gross.
	hdr, err := encode(&p.packetHeader)
	if err != nil {
		return nil, err
	}
	left -= len(hdr)
	assert(left >= len(payload))

	p.payload = payload
	protected := aead.Seal(nil, c.packetNonce(p.PacketNumber), p.payload, hdr)
	packet := append(hdr, protected...)

	c.log(logTypeTrace, "Sending packet len=%d, len=%v", len(packet), hex.EncodeToString(packet))
	c.congestion.onPacketSent(pn, containsOnlyAcks, len(packet)) //TODO(piet@devae.re) check isackonly
	c.transport.Send(packet)

	return packet, nil
}

// Send a packet with whatever PT seems appropriate now.
func (c *Connection) sendPacketNow(tosend []frame, containsOnlyAcks bool) ([]byte, error) {
	return c.sendPacket(packetTypeProtectedShort, tosend, containsOnlyAcks)
}

// Send a packet with a specific PT.
func (c *Connection) sendPacket(pt uint8, tosend []frame, containsOnlyAcks bool) ([]byte, error) {
	sent := 0

	payload := make([]byte, 0)

	for _, f := range tosend {
		_, err := f.length()
		if err != nil {
			return nil, err
		}

		c.log(logTypeTrace, "Frame=%v", hex.EncodeToString(f.encoded))

		{
			msd, ok := f.f.(*maxStreamDataFrame)
			if ok {
				c.log(logTypeFlowControl, "EKR: PT=%x Sending maxStreamDate %v %v", c.nextSendPacket, msd.StreamId, msd.MaximumStreamData)
			}

		}
		payload = append(payload, f.encoded...)
		sent++
	}

	connId := c.serverConnId
	if c.role == RoleClient {
		if pt == packetTypeInitial {
			connId = c.clientConnId
		}
	} else {
		if pt == packetTypeRetry {
			connId = c.clientConnId
		}
	}

	pn := c.nextSendPacket
	c.nextSendPacket++

	return c.sendPacketRaw(pt, connId, pn, c.version, payload, containsOnlyAcks)
}

func (c *Connection) sendFramesInPacket(pt uint8, tosend []frame) error {
	c.log(logTypeConnection, "%s: Sending packet of type %v. %v frames", c.label(), pt, len(tosend))
	c.log(logTypeTrace, "Sending packet of type %v. %v frames", pt, len(tosend))
	left := c.mtu

	var connId ConnectionId
	var aead cipher.AEAD
	if c.writeProtected != nil {
		aead = c.writeProtected.aead
	}
	connId = c.serverConnId

	longHeader := true
	if c.role == RoleClient {
		switch {
		case pt == packetTypeInitial:
			aead = c.writeClear.aead
			connId = c.clientConnId
		case pt == packetTypeHandshake:
			aead = c.writeClear.aead
		case pt == packetType0RTTProtected:
			connId = c.clientConnId
			aead = nil // This will cause a crash b/c 0-RTT doesn't work yet
		default:
			longHeader = false
		}
	} else {
		if pt == packetTypeHandshake {
			aead = c.writeClear.aead
		} else {
			longHeader = true
		}
	}

	left -= aead.Overhead()

	npt := pt
	if longHeader {
		npt |= packetFlagLongHeader
	}
	pn := c.nextSendPacket
	p := packet{
		packetHeader{
			npt,
			connId,
			c.version,
			pn,
		},
		nil,
	}
	c.nextSendPacket++

	// Encode the header so we know how long it is.
	// TODO(ekr@rtfm.com): this is gross.
	hdr, err := encode(&p.packetHeader)
	if err != nil {
		return err
	}
	left -= len(hdr)

	sent := 0

	for _, f := range tosend {
		l, err := f.length()
		if err != nil {
			return err
		}

		assert(l <= left)

		c.log(logTypeTrace, "Frame=%v", hex.EncodeToString(f.encoded))
		p.payload = append(p.payload, f.encoded...)
		sent++
	}

	protected := aead.Seal(nil, c.packetNonce(p.PacketNumber), p.payload, hdr)
	packet := append(hdr, protected...)

	c.log(logTypeTrace, "Sending packet len=%d, len=%v", len(packet), hex.EncodeToString(packet))
	c.congestion.onPacketSent(pn, false, len(packet)) //TODO(piet@devae.re) check isackonly
	c.transport.Send(packet)

	return nil
}

func (c *Connection) sendOnStream0(data []byte) error {
	c.log(logTypeConnection, "%v: sending %v bytes on stream 0", c.label(), len(data))
	_, err := c.localBidiStreams[0].Write(data)
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
func (c *Connection) sendCombinedPacket(pt uint8, frames []frame, acks ackRanges, left int) (int, error) {
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

	_, err = c.sendPacket(pt, frames, containsOnlyAcks)
	if err != nil {
		return 0, err
	}

	return asent, nil
}

func (c *Connection) queueFrame(q *[]frame, f frame) {
	*q = append(*q, f)
}

func (c *Connection) enqueueStreamFrames(s SendStream, q *[]frame) {
	if s == nil {
		return
	}
	chunks, _ := s.outputWritable()
	for _, ch := range chunks {
		f := newStreamFrame(s.Id(), ch.offset, ch.data, ch.last)
		c.queueFrame(q, f)
	}
}

// Send all the queued data on a set of streams with packet type |pt|
func (c *Connection) queueStreamFrames(protected bool) error {
	c.log(logTypeConnection, "%v: queueStreamFrames, protected=%v",
		c.label(), protected)

	if !protected {
		s0 := c.localBidiStreams[0]
		c.enqueueStreamFrames(s0, &c.outputClearQ)
		return nil
	}

	// Output all the stream frames that are now permitted by stream flow control
	for _, s := range c.localBidiStreams[1:] {
		c.enqueueStreamFrames(s, &c.outputProtectedQ)
	}
	for _, s := range c.remoteBidiStreams {
		c.enqueueStreamFrames(s, &c.outputProtectedQ)
	}
	for _, s := range c.localUniStreams {
		c.enqueueStreamFrames(s, &c.outputProtectedQ)
	}
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

/* Transmit all the frames permitted by connection level flow control and
* the congestion controller. We're going to need to be more sophisticated
* when we actually do connection level flow control. */
func (c *Connection) sendQueuedFrames(pt uint8, protected bool, bareAcks bool) (int, error) {
	c.log(logTypeConnection, "%v: sendQueuedFrames, pt=%v, protected=%v",
		c.label(), pt, protected)

	acks := c.recvd.prepareAckRange(protected, false)
	now := time.Now()
	txAge := c.retransmitTime * time.Millisecond
	aeadOverhead := c.determineAead(pt).Overhead()
	sent := int(0)
	spaceInCongestionWindow := c.congestion.bytesAllowedToSend()

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
	// The length of the next packet to be send
	spaceInPacket := c.mtu - aeadOverhead - kLongHeaderLength // TODO(ekr@rtfm.com): check header type
	spaceInCongestionWindow -= (aeadOverhead + kLongHeaderLength)

	for i, _ := range *queue {
		f := &((*queue)[i])
		// c.log(logTypeStream, "Examining frame=%v", f)

		frameLength, err := f.length()
		if err != nil {
			return 0, err
		}

		cAge := now.Sub(f.time)
		if f.needsTransmit {
			c.log(logTypeStream, "Frame %f requires transmission", f.String())
		} else if cAge < txAge {
			c.log(logTypeStream, "Skipping frame %f because sent too recently", f.String())
			continue
		}

		// if there is no more space in the congestion window, stop
		// trying to send stuff
		if spaceInCongestionWindow < frameLength {
			break
		}

		c.log(logTypeStream, "Sending frame %s, age = %v", f.String(), cAge)
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
			spaceInPacket = c.mtu - aeadOverhead - kLongHeaderLength // TODO(ekr@rtfm.com): check header type
			spaceInCongestionWindow -= (aeadOverhead + kLongHeaderLength)
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
	c.log(logTypeConnection, "%s: Remainder to send? sent=%v frames=%v acks=%v bareAcks=%v",
		c.label(), sent, len(frames), len(acks), bareAcks)
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
	for _, s := range c.localBidiStreams {
		n += s.outstandingQueuedBytes()
	}
	for _, s := range c.remoteBidiStreams {
		n += s.outstandingQueuedBytes()
	}
	for _, s := range c.localUniStreams {
		n += s.outstandingQueuedBytes()
	}

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
func (c *Connection) Input(p []byte) error {
	return c.handleError(c.input(p))
}

func (c *Connection) fireReadable() {
	if c.handler == nil {
		return
	}

	fire := func(s RecvStream) {
		if s != nil && s.clearReadable() {
			c.handler.StreamReadable(s)
		}
	}

	for _, s := range c.localBidiStreams[1:] {
		fire(s)
	}
	for _, s := range c.remoteBidiStreams {
		fire(s)
	}
	for _, s := range c.remoteUniStreams {
		fire(s)
	}
}

func (c *Connection) input(p []byte) error {
	if c.isClosed() {
		return ErrorConnIsClosed
	}

	if c.state == StateClosing {
		c.log(logTypeConnection, "Discarding packet while closing (closePacket=%v)", c.closePacket != nil)
		if c.closePacket != nil {
			c.transport.Send(c.closePacket)
		}
		return nil
	}

	c.lastInput = time.Now()

	var hdr packetHeader

	c.log(logTypeTrace, "Receiving packet len=%v %v", len(p), hex.EncodeToString(p))
	hdrlen, err := decode(&hdr, p)
	if err != nil {
		c.log(logTypeConnection, "Could not decode packetX: %v", hex.EncodeToString(p))
		return wrapE(ErrorInvalidPacket, err)
	}
	assert(int(hdrlen) <= len(p))

	if isLongHeader(&hdr) && hdr.Version != c.version {
		if c.role == RoleServer {
			c.log(logTypeConnection, "%s: Received unsupported version %v, expected %v", c.label(), hdr.Version, c.version)
			err = c.sendVersionNegotiation(hdr.ConnectionID, hdr.PacketNumber, hdr.Version)
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
	c.log(logTypeFlowControl, "EKR: Received packet %x len=%d", hdr.PacketNumber, len(p))
	c.log(logTypeConnection, "Packet header %v, %d", hdr, typ)

	if isLongHeader(&hdr) && hdr.Version == 0 {
		return c.processVersionNegotiation(&hdr, p[hdrlen:])
	}

	if c.state == StateWaitClientInitial {
		if typ != packetTypeInitial {
			c.log(logTypeConnection, "Received unexpected packet before client initial")
			return nil
		}
		// TODO(ekr@rtfm.com): This will result in connection ID flap if we
		// receive a new connection from the same tuple with a different conn ID.
		c.clientConnId = hdr.ConnectionID
		err := c.setupAeadMasking()
		if err != nil {
			return err
		}
	}

	aead := c.readClear.aead
	if hdr.isProtected() {
		if c.readProtected == nil {
			c.log(logTypeConnection, "Received protected data before crypto state is ready")
			return nil
		}
		aead = c.readProtected.aead
	}

	// TODO(ekr@rtfm.com): this dup detection doesn't work right if you
	// get a cleartext packet that has the same PN as a ciphertext or vice versa.
	// Need to fix.
	c.log(logTypeConnection, "%s: Received (unverified) packet with PN=%x PT=%v",
		c.label(), hdr.PacketNumber, hdr.getHeaderType())

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

	naf := true
	switch typ {
	case packetTypeInitial:
		err = c.processClientInitial(&hdr, payload)
	case packetTypeHandshake:
		err = c.processCleartext(&hdr, payload, &naf)
	case packetTypeProtectedShort:
		err = c.processUnprotected(&hdr, packetNumber, payload, &naf)
	default:
		c.log(logTypeConnection, "Unsupported packet type %v", typ)
		err = internalError("Unsupported packet type %v", typ)
	}
	c.recvd.packetSetReceived(packetNumber, hdr.isProtected(), naf)
	if err != nil {
		return err
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
		_, err = c.sendPacketRaw(packetTypeRetry, hdr.ConnectionID, hdr.PacketNumber, kQuicVersion, sf.encoded, false)
		return err
	}

	stream0 := c.localBidiStreams[0].(*stream)
	stream0.recvStreamBase.offset = uint64(len(sf.Data))
	c.setTransportParameters()

	err = c.sendOnStream0(sflt)
	if err != nil {
		return err
	}

	c.setState(StateWaitClientSecondFlight)

	return err
}

func (c *Connection) processCleartext(hdr *packetHeader, payload []byte, naf *bool) error {
	*naf = false
	c.log(logTypeHandshake, "Reading cleartext in state %v", c.state)
	// TODO(ekr@rtfm.com): Need clearer state checks.
	/*
		We should probably reinstate this once we have encrypted ACKs.

		if c.state != StateWaitServerFirstFlight && c.state != StateWaitClientSecondFlight {
			c.log(logTypeConnection, "Received cleartext packet in inappropriate state. Ignoring")
			return nil
		}*/

	stream0 := c.localBidiStreams[0].(*stream)
	for len(payload) > 0 {
		c.log(logTypeConnection, "%s: payload bytes left %d", c.label(), len(payload))
		n, f, err := decodeFrame(payload)
		if err != nil {
			c.log(logTypeConnection, "Couldn't decode frame %v", err)
			return wrapE(ErrorInvalidPacket, err)
		}
		c.log(logTypeHandshake, "Frame type %v", f.f.getType())

		payload = payload[n:]
		nonAck := true
		switch inner := f.f.(type) {
		case *paddingFrame:
			// Skip.

		case *maxStreamDataFrame:
			if inner.StreamId != 0 {
				return ErrorProtocolViolation
			}
			stream0.processMaxStreamData(inner.MaximumStreamData)

		case *streamFrame:
			// If this is duplicate data and if so early abort.
			if inner.Offset+uint64(len(inner.Data)) <= stream0.recvStreamBase.offset {
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
				// 3. Remember the connection ID
				if len(c.clientInitial) > 0 {
					stream0.sendStreamBase.offset = uint64(len(c.clientInitial))
					c.clientInitial = nil
					c.serverConnId = hdr.ConnectionID
				}
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

			err = c.newFrameData(stream0, inner)
			if err != nil {
				return err
			}
			available, err := ioutil.ReadAll(stream0)
			if err != nil && err != ErrorWouldBlock {
				return err
			}
			// c.issueStreamCredit(c.streams[0], len(available))
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
			nonAck = false

		case *connectionCloseFrame:
			c.log(logTypeConnection, "Received frame close")
			c.setState(StateClosed)
			return fatalError("Connection closed")

		default:
			c.log(logTypeConnection, "Received unexpected frame type")
			return fatalError("Unexpected frame type: %v", f.f.getType())
		}
		if nonAck {
			*naf = true
		}
	}

	return nil
}

func (c *Connection) sendVersionNegotiation(connId ConnectionId, pn uint64, version VersionNumber) error {
	p := newVersionNegotiationPacket([]VersionNumber{
		c.version,
		kQuicGreaseVersion1,
	})
	b, err := encode(p)
	if err != nil {
		return err
	}

	// Generate a random packet type.
	pt, err := generateRand64()
	if err != nil {
		return err
	}

	return c.sendSpecialClearPacket(uint8((pt&0x7f)|packetFlagLongHeader), connId, pn, 0, b)
}

func (c *Connection) processVersionNegotiation(hdr *packetHeader, payload []byte) error {
	c.log(logTypeConnection, "%s: Processing version negotiation packet", c.label())
	if c.recvd.initialized() {
		c.log(logTypeConnection, "%s: Ignoring version negotiation after received another packet", c.label())
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
	c.log(logTypeConnection, "%s: Processing stateless retry packet %s", c.label(), dumpPacket(payload))
	if c.recvd.initialized() {
		c.log(logTypeConnection, "%s: Ignoring stateless retry after received another packet", c.label())
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

func (c *Connection) issueStreamCredit(s RecvStream, max uint64) error {
	// Don't issue credit for stream 0 during the handshake.
	if s.Id() == 0 && c.state != StateEstablished {
		return nil
	}

	// Remove other MAX_STREAM_DATA frames so we don't retransmit them. This violates
	// the current spec, but offline we all agree it's silly. See:
	// https://github.com/quicwg/base-drafts/issues/806
	c.outputProtectedQ = filterFrames(c.outputProtectedQ, func(f *frame) bool {
		inner, ok := f.f.(*maxStreamDataFrame)
		if !ok {
			return true
		}
		return !(inner.StreamId == s.Id())
	})

	c.queueFrame(&c.outputProtectedQ, newMaxStreamData(s.Id(), max))
	c.log(logTypeFlowControl, "Issuing more stream credit for stream %d new offset=%d", s.Id(), max)

	// TODO(ekr@rtfm.com): We do need to do something to send this
	// immediately, because we don't always.
	return nil
}

func (c *Connection) issueStreamIdCredit(t streamType) error {

	// TODO work out how to issue in more reasonable increments.
	var max uint64
	switch t {
	case streamTypeBidirectionalRemote:
		max = (uint64(c.maxRemoteBidi) + 1) << 2
		if c.role == RoleServer {
			max++
		}
	case streamTypeUnidirectionalRemote:
		max = (uint64(c.maxRemoteUni) + 1) << 2
	}
	max |= t.suffix(c.role)
	c.outputProtectedQ = filterFrames(c.outputProtectedQ, func(f *frame) bool {
		_, ok := f.f.(*maxStreamIdFrame)
		return !ok
	})

	c.queueFrame(&c.outputProtectedQ, newMaxStreamId(max))
	c.log(logTypeFlowControl, "Issuing more %v stream ID credit: %d", t, max)

	// TODO(ekr@rtfm.com): We do need to do something to send this
	// immediately, because we don't always.
	return nil
}

func (c *Connection) processUnprotected(hdr *packetHeader, packetNumber uint64, payload []byte, naf *bool) error {
	c.log(logTypeHandshake, "Reading unprotected data in state %v", c.state)
	c.log(logTypeConnection, "Received Packet=%v", dumpPacket(payload))
	*naf = false
	for len(payload) > 0 {
		c.log(logTypeConnection, "%s: payload bytes left %d", c.label(), len(payload))
		n, f, err := decodeFrame(payload)
		if err != nil {
			c.log(logTypeConnection, "Couldn't decode frame %v", err)
			return err
		}
		c.log(logTypeConnection, "Frame type %v", f.f.getType())

		payload = payload[n:]
		nonAck := true
		switch inner := f.f.(type) {
		case *paddingFrame:
			// Skip.
		case *rstStreamFrame:
			// TODO(ekr@rtfm.com): Don't let the other side initiate
			// streams that are the wrong parity.
			c.log(logTypeStream, "Received RST_STREAM on stream %v", inner.StreamId)
			s, err := c.ensureRecvStream(inner.StreamId)
			if err != nil {
				return err
			}

			err = s.handleReset(inner.FinalOffset)
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

		case *maxStreamDataFrame:
			s, err := c.ensureSendStream(inner.StreamId)
			if err != nil {
				return err
			}
			s.processMaxStreamData(inner.MaximumStreamData)

		case *maxStreamIdFrame:
			switch streamTypeFromId(inner.MaximumStreamId, c.role) {
			case streamTypeBidirectionalLocal:
				c.maxLocalBidi = int(inner.MaximumStreamId >> 2)
			case streamTypeUnidirectionalLocal:
				c.maxLocalUni = int(inner.MaximumStreamId >> 2)
			default:
				return ErrorProtocolViolation
			}
			if c.role == RoleClient {
				c.maxLocalBidi++
			}

		case *ackFrame:
			//			c.log(logTypeConnection, "Received ACK, first range=%v-%v", inner.LargestAcknowledged-inner.AckBlockLength, inner.LargestAcknowledged)
			err = c.processAckFrame(inner, true)
			if err != nil {
				return err
			}
			nonAck = false

		case *streamBlockedFrame:
			s, err := c.ensureRecvStream(inner.StreamId)
			if err != nil {
				return err
			}
			c.log(logTypeFlowControl, "stream %d is blocked", s.Id())

		case *streamFrame:
			c.log(logTypeTrace, "Received on stream %v %x", inner.StreamId, inner.Data)
			s, err := c.ensureRecvStream(inner.StreamId)
			if err != nil {
				return err
			}

			err = c.newFrameData(s, inner)
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

		default:
			c.log(logTypeConnection, "Received unexpected frame type")
		}
		if nonAck {
			*naf = true
		}
	}

	return nil
}

func (c *Connection) newFrameData(s RecvStream, inner *streamFrame) error {
	err := s.newFrameData(inner.Offset, inner.hasFin(), inner.Data)
	if err != nil {
		return err
	}
	max, credit := s.creditMaxStreamData()
	if credit {
		c.issueStreamCredit(s, max)
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
		c.log(logTypeConnection, "%s: processing ACK for PN=%x", c.label(), pn)

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
	c.log(logTypeAck, "%s: processing ACK last=%x first ack block=%d", c.label(), f.LargestAcknowledged, f.FirstAckBlock)
	end := f.LargestAcknowledged

	start := (end - f.FirstAckBlock)

	// Decode ACK Delay
	ackDelayMicros := QuicFloat16(f.AckDelay).Float32()
	ackDelay := time.Duration(ackDelayMicros * 1e3)

	// Process the First ACK Block
	c.log(logTypeAck, "%s: processing ACK range %x-%x", c.label(), start, end)
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
			c.log(logTypeAck, "%s: encountered empty ACK block", c.label())
			continue
		}

		last = start
		c.log(logTypeAck, "%s: processing ACK range %x-%x", c.label(), start, end)
		c.processAckRange(start, end, protected)
		receivedAcks = append(receivedAcks, ackRange{end, end - start})
	}

	c.congestion.onAckReceived(receivedAcks, ackDelay)

	return nil
}

// Check the connection's timer and process any events whose time has
// expired in the meantime. This includes sending retransmits, etc.
func (c *Connection) CheckTimer() (int, error) {
	if c.isClosed() {
		return 0, ErrorConnIsClosed
	}

	c.log(logTypeConnection, "Checking timer")

	if time.Now().After(c.lastInput.Add(time.Second * time.Duration(c.idleTimeout))) {
		c.log(logTypeConnection, "Connection is idle for more than %v", c.idleTimeout)
		return 0, ErrorConnectionTimedOut
	}

	if c.state == StateClosing {
		if time.Now().After(c.closingEnd) {
			c.log(logTypeConnection, "End of draining period, closing")
			c.setState(StateClosed)
		}
		return 0, ErrorConnIsClosed
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
	stream0 := c.localBidiStreams[0].(*stream)
	stream0.sendStreamBase.maxStreamData = uint64(c.tpHandler.peerParams.maxStreamsData)

	c.maxLocalBidi = int(c.tpHandler.peerParams.maxStreamIdBidi >> 2)
	c.maxLocalUni = int(c.tpHandler.peerParams.maxStreamIdUni >> 2)
	if c.role == RoleClient {
		c.maxLocalBidi++
	}
}

func (c *Connection) setupAeadMasking() (err error) {
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
	connId := encodeArgs(c.clientConnId)
	c.writeClear, err = newCryptoStateFromSecret(connId, sendLabel, &params)
	if err != nil {
		return
	}
	c.readClear, err = newCryptoStateFromSecret(connId, recvLabel, &params)
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

// Create a stream on a given connection. Returns the created
// stream.
func (c *Connection) CreateBidirectionalStream() Stream {
	// First check to see if we might exceed maxStreamId
	if len(c.localBidiStreams) >= c.maxLocalBidi {
		return nil
	}

	id := (uint64(len(c.localBidiStreams)) << 2) | streamTypeBidirectionalLocal.suffix(c.role)
	c.log(logTypeStream, "Creating stream %v", id)
	s, _ := c.ensureLocalBidiStream(id)
	return s
}

// Create a stream on a given connection. Returns the created
// stream.
func (c *Connection) CreateUnirectionalStream() SendStream {
	// First check to see if we might exceed maxStreamId
	if len(c.localUniStreams) >= c.maxLocalUni {
		return nil
	}

	id := (uint64(len(c.localUniStreams)) << 2) | streamTypeUnidirectionalLocal.suffix(c.role)
	c.log(logTypeStream, "Creating stream %v", id)
	s, _ := c.ensureLocalUniStream(id)
	return s
}

// GetBidirectionalStream retrieves a stream with the given id. Returns nil if
// no such stream exists.
func (c *Connection) GetBidirectionalStream(id uint64) Stream {

	var streams []Stream
	switch streamTypeFromId(id, c.role) {
	case streamTypeBidirectionalLocal:
		streams = c.localBidiStreams
	case streamTypeBidirectionalRemote:
		streams = c.remoteBidiStreams
	default:
		return nil
	}
	index := int(id >> 2)
	if index >= len(streams) {
		return nil
	}
	return streams[index]
}

// GetLocalUnidirectionalStream retrieves a stream with the given id. Returns
// nil if no such stream exists.
func (c *Connection) GetLocalUnidirectionalStream(id uint64) SendStream {
	if streamTypeFromId(id, c.role) != streamTypeUnidirectionalLocal {
		return nil
	}
	index := int(id >> 2)
	if index >= len(c.localUniStreams) {
		return nil
	}
	return c.localUniStreams[index]
}

// GetRemoteUnidirectionalStream retrieves a stream with the given id. Returns
// nil if no such stream exists.
func (c *Connection) GetRemoteUnidirectionalStream(id uint64) RecvStream {
	if streamTypeFromId(id, c.role) != streamTypeUnidirectionalRemote {
		return nil
	}
	index := int(id >> 2)
	if index >= len(c.remoteUniStreams) {
		return nil
	}
	return c.remoteUniStreams[index]
}

func generateRand64() (uint64, error) {
	b := make([]byte, 8)

	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}

	ret := uint64(0)
	for _, c := range b {
		ret <<= 8
		ret |= uint64(c)
	}

	return ret, nil
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

	c.closingEnd = time.Now().Add(3 * c.congestion.rto())
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
	c.log(logTypeConnection, "%v Close()", c.label())
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

// Get the connection ID for a connection. Returns 0 if
// you are a client and the first server packet hasn't
// been received.
func (c *Connection) Id() ConnectionId {
	return c.serverConnId
}

func (c *Connection) ClientId() ConnectionId {
	return c.clientConnId
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
	logf(logTypeConnection, "%v: failed with Error=%v", c.label(), e.Error())
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
