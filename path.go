package minq

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
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
	verificationHmac    hash.Hash
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

func (p *path) calculateChallenge(i byte) []byte {
	ctr := []byte{i}
	return append(ctr, p.verificationHmac.Sum(ctr)[:7]...)
}

func (p *path) GeneratePathChallenge() (*frame, error) {
	if p.verificationCounter == ^byte(0) {
		return nil, errors.New("too many challenges")
	}
	if p.verificationHmac == nil {
		k := make([]byte, 32)
		_, err := io.ReadFull(rand.Reader, k)
		if err != nil {
			return nil, err
		}
		p.verificationHmac = hmac.New(sha256.New, k)
		p.verificationCounter = 0
	}
	challenge := p.calculateChallenge(p.verificationCounter)
	p.verificationCounter++
	return newPathChallengeFrame(challenge), nil
}

func (p *path) VerifyPathResponse(response []byte) bool {
	if p.verificationHmac == nil {
		return false
	}
	expected := p.calculateChallenge(response[0])
	if !hmac.Equal(expected, response) {
		return false
	}
	p.SetVerified()
	return true
}

func (p *path) SetVerified() {
	p.packetsAllowed = ^uint(0)
}
