package minq

import (
	"encoding/hex"
	"fmt"
	"io"
)

// SendStreamState is the state of a SendStream
type SendStreamState uint8

// SendStreamState values.  Not all of these are tracked
const (
	SendStreamStateOpen        = SendStreamState(0)
	SendStreamStateSend        = SendStreamState(1)
	SendStreamStateCloseQueued = SendStreamState(2) // Not in the spec``
	SendStreamStateDataSent    = SendStreamState(3)
	SendStreamStateResetSent   = SendStreamState(4)
	SendStreamStateDataRecvd   = SendStreamState(5) // Not tracked
	SendStreamStateResetRecvd  = SendStreamState(6) // Not tracked
)

// RecvStreamState is the state of a RecvStream
type RecvStreamState uint8

// RecvStreamState values.  Not all of these are tracked.
const (
	RecvStreamStateRecv       = RecvStreamState(0)
	RecvStreamStateSizeKnown  = RecvStreamState(1)
	RecvStreamStateDataRecvd  = RecvStreamState(2) // Not tracked
	RecvStreamStateResetRecvd = RecvStreamState(3)
	RecvStreamStateDataRead   = RecvStreamState(4)
	RecvStreamStateResetRead  = RecvStreamState(5) // Not tracked
)

// The structure here is a little convoluted.
//
// There are three primary interfaces: SendStream, RecvStream, and Stream. These
// all implement hasIdentity and one or both (for Stream) of sendStreamMethods
// or recvStreamMethods.
//
// The implementations are layered.
//
// streamCommon is at the bottom, it includes stuff common to sending and receiving.
//
// sendStreamBase and recvStreamBase add sending and receiving functions. These
// know how to send and receive, but don't know about identifiers or
// connections.  This allows them to be tested in isolation.
//
// Those types don't know about connections, so sendStream and recvStream add
// that by mixing in streamWithIdentity. The same applies to stream, which mixes
// both sendStream and recvStream. These include the concrete implementations of
// the interfaces.

type hasIdentity interface {
	Id() uint64
}

type sendStreamMethods interface {
	io.WriteCloser
	Reset(ErrorCode) error
	SendState() SendStreamState
}

type sendStreamPrivateMethods interface {
	setSendState(SendStreamState)
	outstandingQueuedBytes() int
	processMaxStreamData(uint64)
	outputWritable() ([]streamChunk, bool)
}

type recvStreamMethods interface {
	io.Reader
	StopSending(ErrorCode) error
	RecvState() RecvStreamState
}

type recvStreamPrivateMethods interface {
	setRecvState(RecvStreamState)
	handleReset(offset uint64) error
	clearReadable() bool
	newFrameData(uint64, bool, []byte) error
	creditMaxStreamData() (uint64, bool)
}

// SendStream can send.
type SendStream interface {
	hasIdentity
	sendStreamMethods
}

type sendStreamPrivate interface {
	SendStream
	sendStreamPrivateMethods
}

// RecvStream can receive.
type RecvStream interface {
	hasIdentity
	recvStreamMethods
}

type recvStreamPrivate interface {
	RecvStream
	recvStreamPrivateMethods
}

// Stream is both a send and receive stream.
type Stream interface {
	hasIdentity
	sendStreamMethods
	recvStreamMethods
}

type streamPrivate interface {
	Stream
	sendStreamPrivateMethods
	recvStreamPrivateMethods
}

type streamChunk struct {
	offset uint64
	last   bool
	data   []byte
}

func (sc streamChunk) String() string {
	return fmt.Sprintf("chunk(offset=%v, len=%v, last=%v)", sc.offset, len(sc.data), sc.last)
}

type streamCommon struct {
	log           loggingFunction
	offset        uint64
	chunks        []streamChunk
	maxStreamData uint64
}

func (s *streamCommon) insertSortedChunk(offset uint64, last bool, payload []byte) {
	c := streamChunk{offset, last, dup(payload)}
	s.log(logTypeStream, "insert %v, current offset=%v", c, s.offset)
	s.log(logTypeTrace, "payload %v", hex.EncodeToString(payload))
	nchunks := len(s.chunks)

	// First check if we can append the new slice at the end
	if l := nchunks; l == 0 || offset > s.chunks[l-1].offset {
		s.chunks = append(s.chunks, c)
	} else {
		// Otherwise find out where it should go
		var i int
		for i = 0; i < nchunks; i++ {
			if offset < s.chunks[i].offset {
				break
			}
		}

		// This may not be the fastest way to do this splice.
		tmp := make([]streamChunk, 0, nchunks+1)
		tmp = append(tmp, s.chunks[:i]...)
		tmp = append(tmp, c)
		tmp = append(tmp, s.chunks[i:]...)
		s.chunks = tmp
	}
	s.log(logTypeStream, "Stream now has %v chunks", nchunks)
}

type sendStreamBase struct {
	streamCommon
	state   SendStreamState
	blocked bool // Have we returned blocked
}

func (s *sendStreamBase) setSendState(state SendStreamState) {
	if state != s.state {
		s.log(logTypeStream, "set state %v->%v", s.state, state)
		s.state = state
	}
}

// SendState returns the current state of the receive stream.
func (s *sendStreamBase) SendState() SendStreamState {
	return s.state
}

func (s *sendStreamBase) queue(payload []byte) error {
	s.log(logTypeStream, "queueing %v bytes", len(payload))
	s.insertSortedChunk(s.offset, false, payload)
	s.offset += uint64(len(payload))
	return nil
}

func (s *sendStreamBase) write(data []byte) error {
	switch s.state {
	case SendStreamStateOpen:
		s.setSendState(SendStreamStateSend)
	case SendStreamStateSend:
		// OK to send
	default:
		return ErrorStreamIsClosed
	}
	for len(data) > 0 {
		tocpy := 1024
		if tocpy > len(data) {
			tocpy = len(data)
		}
		err := s.queue(data[:tocpy])
		if err != nil {
			return err
		}

		data = data[tocpy:]
	}

	return nil
}

func (s *sendStreamBase) outstandingQueuedBytes() int {
	n := 0
	for _, ch := range s.chunks {
		n += len(ch.data)
	}
	return n
}

// Push out all the frames permitted by flow control.
func (s *sendStreamBase) outputWritable() ([]streamChunk, bool) {
	s.log(logTypeStream, "outputWritable, current max offset=%d)", s.maxStreamData)
	out := make([]streamChunk, 0)
	blocked := false
	for len(s.chunks) > 0 {
		ch := s.chunks[0]
		if ch.offset+uint64(len(ch.data)) > s.maxStreamData {
			blocked = true
			s.log(logTypeFlowControl, "stream blocked at maxStreamData=%d, chunk(offset=%d, len=%d)", s.maxStreamData, ch.offset, len(ch.data))
			break
		}
		out = append(out, ch)
		s.chunks = s.chunks[1:]
		if ch.last {
			s.setSendState(SendStreamStateDataSent)
		}
	}

	if s.blocked {
		// Don't return blocked > once
		blocked = false
	} else {
		s.blocked = blocked
	}
	return out, blocked
}

func (s *sendStreamBase) processMaxStreamData(offset uint64) {
	if offset < s.maxStreamData {
		return
	}
	s.log(logTypeFlowControl, "max send offset set to %d", offset)
	s.maxStreamData = offset
}

func (s *sendStreamBase) close() {
	switch s.state {
	case SendStreamStateOpen, SendStreamStateSend:
		s.insertSortedChunk(s.offset, true, nil)
		s.setSendState(SendStreamStateCloseQueued)
	default:
		// NOOP
	}
}

type recvStreamBase struct {
	streamCommon
	state        RecvStreamState
	lastReceived uint64
	readable     bool
}

func (s *recvStreamBase) setRecvState(state RecvStreamState) {
	if state != s.state {
		s.log(logTypeStream, "set state %v->%v", s.state, state)
		s.state = state
	}
}

// RecvState returns the current state of the receive stream.
func (s *recvStreamBase) RecvState() RecvStreamState {
	return s.state
}

// clearReadable clears the readable flag and returns true if it was set.
func (s *recvStreamBase) clearReadable() bool {
	r := s.readable
	s.readable = false
	return r
}

// Add data to a stream. Return true if this is readable now.
func (s *recvStreamBase) newFrameData(offset uint64, last bool, payload []byte) error {
	s.log(logTypeStream, "New data offset=%d, len=%d", offset, len(payload))

	end := offset + uint64(len(payload))
	if s.maxStreamData < s.lastReceived {
		return ErrorFrameFormatError
	}
	if last {
		if end < s.lastReceived {
			return ErrorProtocolViolation
		}
		s.lastReceived = end
		if s.state == RecvStreamStateRecv {
			s.setRecvState(RecvStreamStateSizeKnown)
		}
	} else if end > s.lastReceived {
		if s.state != RecvStreamStateRecv {
			// We shouldn't be increasing lastReceived in any other state.
			return ErrorProtocolViolation
		}
		s.lastReceived = end
	}
	if s.state != RecvStreamStateRecv && s.state != RecvStreamStateSizeKnown {
		// We shouldn't be increasing lastReceived in RecvStreamStateSizeKnown.
		return nil
	}

	s.insertSortedChunk(offset, last, payload)
	if s.chunks[0].offset <= s.offset {
		s.readable = true
	}

	return nil
}

// Read from a stream into a buffer. Up to |len(b)| bytes will be read,
// and the number of bytes returned is in |n|.
func (s *recvStreamBase) read(b []byte) (int, error) {
	s.log(logTypeStream, "Reading len = %v current chunks=%v", len(b), len(s.chunks))

	read := 0

	for len(b) > 0 {
		if len(s.chunks) == 0 {
			break
		}

		chunk := s.chunks[0]

		// We have a gap.
		if chunk.offset > s.offset {
			break
		}

		// Remove leading bytes
		remove := s.offset - chunk.offset
		if remove > uint64(len(chunk.data)) {
			// Nothing left.
			s.chunks = s.chunks[1:]
			continue
		}

		chunk.offset += remove
		chunk.data = chunk.data[remove:]

		// Now figure out how much we can read
		n := copy(b, chunk.data)
		chunk.data = chunk.data[n:]
		chunk.offset += uint64(n)
		s.offset += uint64(n)
		b = b[n:]
		read += n

		// This chunk is empty.
		if len(chunk.data) == 0 {
			s.chunks = s.chunks[1:]

			if chunk.last {
				s.setRecvState(RecvStreamStateDataRead)
				s.chunks = nil
				break
			}
		}
	}

	// If we have read no data, say we would have blocked.
	if read == 0 {
		switch s.state {
		case RecvStreamStateRecv, RecvStreamStateSizeKnown:
			return 0, ErrorWouldBlock
		default:
			if s.chunks == nil {
				return 0, io.EOF
			}
			return 0, ErrorStreamIsClosed
		}
	}
	return read, nil
}

func (s *recvStreamBase) handleReset(offset uint64) error {
	switch s.state {
	case RecvStreamStateRecv:
		s.lastReceived = offset
	case RecvStreamStateDataRecvd, RecvStreamStateResetRead:
		panic("we don't use this state")
	case RecvStreamStateSizeKnown, RecvStreamStateDataRead:
		if offset != s.lastReceived {
			return ErrorProtocolViolation
		}
	default:
		panic("unknown state")
	}
	s.setRecvState(RecvStreamStateResetRecvd)
	s.chunks = nil
	return nil
}

func (s *recvStreamBase) creditMaxStreamData() (uint64, bool) {
	remaining := s.maxStreamData - s.lastReceived
	s.log(logTypeFlowControl, "%d bytes of credit remaining, lastReceived=%d",
		remaining, s.lastReceived)
	credit := false
	if remaining < kInitialMaxStreamData/2 {
		credit = true

		max := ^uint64(0)
		if max-s.maxStreamData > kInitialMaxStreamData {
			max = s.maxStreamData + kInitialMaxStreamData
		}
		s.maxStreamData = max
	}

	return s.maxStreamData, credit
}

type streamWithIdentity struct {
	c  *Connection
	id uint64
}

// Id returns the identifier of the stream.
func (s *streamWithIdentity) Id() uint64 {
	return s.id
}

// SendStream is a unidirectional stream for sending.
type sendStream struct {
	streamWithIdentity
	sendStreamBase
}

// Compile-time interface check.
var _ SendStream = &sendStream{}

func newSendStream(c *Connection, id uint64, initialMax uint64) sendStreamPrivate {
	return &sendStream{
		streamWithIdentity: streamWithIdentity{c, id},
		sendStreamBase: sendStreamBase{
			streamCommon: streamCommon{
				log:           newStreamLogger(id, "send", c.log),
				maxStreamData: initialMax,
			},
			state:   SendStreamStateOpen,
			blocked: false,
		},
	}
}

func writeOnStream(s *sendStreamBase, c *Connection, data []byte) (int, error) {
	if c.isClosed() {
		return 0, ErrorConnIsClosed
	}

	err := s.write(data)
	if err != nil {
		return 0, err
	}

	c.sendQueued(false)
	return len(data), nil
}

// Write writes data.
func (s *sendStream) Write(data []byte) (int, error) {
	return writeOnStream(&s.sendStreamBase, s.c, data)
}

func closeStream(s *sendStreamBase, c *Connection) error {
	s.close()
	c.sendQueued(false)
	return nil
}

// Close make the stream end cleanly.
func (s *sendStream) Close() error {
	return closeStream(&s.sendStreamBase, s.c)
}

func resetStream(s *sendStreamBase, id uint64, code ErrorCode, c *Connection) error {
	s.setSendState(SendStreamStateResetSent)
	f := newRstStreamFrame(id, code, s.offset)
	return c.sendFrame(f)
}

// Reset abandons writing on the stream.
func (s *sendStream) Reset(code ErrorCode) error {
	return resetStream(&s.sendStreamBase, s.id, code, s.c)
}

// RecvStream is a unidirectional stream for receiving.
type recvStream struct {
	streamWithIdentity
	recvStreamBase
}

// Compile-time interface check.
var _ RecvStream = &recvStream{}

func newRecvStream(c *Connection, id uint64) recvStreamPrivate {
	return &recvStream{
		streamWithIdentity: streamWithIdentity{c, id},
		recvStreamBase: recvStreamBase{
			streamCommon: streamCommon{
				log:           newStreamLogger(id, "recv", c.log),
				maxStreamData: kInitialMaxStreamData,
			},
			state:    RecvStreamStateRecv,
			readable: false,
		},
	}
}

func readFromStream(s *recvStreamBase, c *Connection, b []byte) (int, error) {
	if c.isClosed() {
		return 0, io.EOF
	}

	n, err := s.read(b)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Read implements io.Reader.
func (s *recvStream) Read(b []byte) (int, error) {
	return readFromStream(&s.recvStreamBase, s.c, b)
}

func stopSending(s *recvStreamBase, id uint64, err ErrorCode, c *Connection) error {
	// TODO implement STOP_SENDING
	return nil
}

// StopSending requests a reset.
func (s *recvStream) StopSending(err ErrorCode) error {
	return stopSending(&s.recvStreamBase, s.id, err, s.c)
}

// Stream is a bidirectional stream.
type stream struct {
	streamWithIdentity
	sendStreamBase
	recvStreamBase
}

// Compile-time interface check.
var _ Stream = &stream{}

func newStream(c *Connection, id uint64, initialMax uint64) streamPrivate {
	return &stream{
		streamWithIdentity: streamWithIdentity{c, id},
		sendStreamBase: sendStreamBase{
			streamCommon: streamCommon{
				log:           newStreamLogger(id, "send", c.log),
				maxStreamData: initialMax,
			},
			state:   SendStreamStateOpen,
			blocked: false,
		},
		recvStreamBase: recvStreamBase{
			streamCommon: streamCommon{
				log:           newStreamLogger(id, "recv", c.log),
				maxStreamData: kInitialMaxStreamData,
			},
			state:    RecvStreamStateRecv,
			readable: false,
		},
	}
}

// Write writes data.
func (s *stream) Write(data []byte) (int, error) {
	return writeOnStream(&s.sendStreamBase, s.c, data)
}

// Read implements io.Reader.
func (s *stream) Read(b []byte) (int, error) {
	return readFromStream(&s.recvStreamBase, s.c, b)
}

// Close make the stream end cleanly.
func (s *stream) Close() error {
	return closeStream(&s.sendStreamBase, s.c)
}

// Reset abandons writing on the stream.
func (s *stream) Reset(code ErrorCode) error {
	return resetStream(&s.sendStreamBase, s.id, code, s.c)
}

// StopSending requests abandoning writing on the stream.
func (s *stream) StopSending(code ErrorCode) error {
	return stopSending(&s.recvStreamBase, s.id, code, s.c)
}
