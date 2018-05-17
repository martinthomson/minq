package minq

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
)

type path struct {
	remoteConnectionId  ConnectionId
	localConnectionId   ConnectionId
	resetToken          []byte
	transport           Transport
	remoteAddr          *net.UDPAddr
	congestion          CongestionController
	mtu                 int
	packetsAllowed      uint
	verificationCounter byte
	verificationKey     []byte
	oldVerificationKey  []byte
}

func (p *path) String() string {
	return fmt.Sprintf("%v_%v", p.localConnectionId, p.remoteConnectionId)
}

func (p *path) Send(pn uint64, packet []byte, ackOnly bool) error {
	if p.packetsAllowed == 0 {
		return ErrorWouldBlock
	}
	p.congestion.onPacketSent(pn, ackOnly, len(packet))
	err := p.transport.Send(packet)
	if p.packetsAllowed < ^uint(0) {
		p.packetsAllowed--
	}
	return err
}

func (p *path) calculateChallenge(i byte, k []byte) []byte {
	first := []byte{i}
	h := sha256.Sum256(append(first, k...))
	return append(first, h[:7]...)
}

func (p *path) GeneratePathChallenge() (*frame, error) {
	if p.verificationKey == nil || p.verificationCounter == 255 {
		p.oldVerificationKey = p.verificationKey
		p.verificationKey = make([]byte, 15)
		_, err := io.ReadFull(rand.Reader, p.verificationKey)
		if err != nil {
			return nil, err
		}
		p.verificationCounter = 0
	}
	challenge := p.calculateChallenge(p.verificationCounter, p.verificationKey)
	p.verificationCounter++
	return newPathChallengeFrame(challenge), nil
}

func (p *path) VerifyPathResponse(response []byte) bool {
	var k []byte
	if response[0] >= p.verificationCounter {
		k = p.oldVerificationKey
	} else {
		k = p.verificationKey
	}
	if k == nil {
		return false
	}
	expected := p.calculateChallenge(response[0], k)
	if !hmac.Equal(expected, response) {
		return false
	}
	p.SetVerified()
	return true
}

func (p *path) SetVerified() {
	p.packetsAllowed = ^uint(0)
}
