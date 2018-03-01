package minq

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/bifurcation/mint"
)

type TlsConfig struct {
	ServerName       string
	CertificateChain []*x509.Certificate
	Key              crypto.Signer
	mintConfig       *mint.Config
	ForceHrr         bool
}

func (c *TlsConfig) init() {
	_ = c.toMint()
}

func (c *TlsConfig) toMint() *mint.Config {
	if c.mintConfig == nil {
		// TODO(ekr@rtfm.com): Provide a real config
		config := mint.Config{
			ServerName:         c.ServerName,
			NonBlocking:        true,
			NextProtos:         []string{kQuicALPNToken},
			SendSessionTickets: true,
		}

		if c.ForceHrr {
			config.RequireCookie = true
		}

		config.CookieProtector, _ = mint.NewDefaultCookieProtector()

		if c.CertificateChain != nil && c.Key != nil {
			config.Certificates =
				[]*mint.Certificate{
					&mint.Certificate{
						Chain:      c.CertificateChain,
						PrivateKey: c.Key,
					},
				}
		}
		config.Init(false)
		c.mintConfig = &config
	}
	return c.mintConfig
}

func NewTlsConfig(serverName string) TlsConfig {
	return TlsConfig{
		ServerName: serverName,
	}
}

type tlsConn struct {
	config   *TlsConfig
	conn     *connBuffer
	tls      *mint.Conn
	finished bool
	cs       *mint.CipherSuiteParams
}

func newTlsConn(conf *TlsConfig, role Role) *tlsConn {
	isClient := true
	if role == RoleServer {
		isClient = false
	}

	c := newConnBuffer()

	return &tlsConn{
		conf,
		c,
		mint.NewConn(c, conf.toMint(), isClient),
		false,
		nil,
	}
}

func (c *tlsConn) setTransportParametersHandler(h *transportParametersHandler) {
	c.tls.SetExtensionHandler(h)
}

func (c *tlsConn) handshake(input []byte) ([]byte, error) {
	logf(logTypeTls, "TLS handshake input len=%v", len(input))
	logf(logTypeTrace, "TLS handshake input = %v", hex.EncodeToString(input))
	if input != nil {
		err := c.conn.input(input)
		if err != nil {
			return nil, err
		}
	}

outer:
	for {
		logf(logTypeTls, "Calling Mint handshake")
		alert := c.tls.Handshake()
		hst := c.tls.GetHsState()
		switch alert {
		case mint.AlertNoAlert, mint.AlertStatelessRetry:
			if hst == mint.StateServerConnected || hst == mint.StateClientConnected {
				st := c.tls.State()

				logf(logTypeTls, "TLS handshake complete")
				logf(logTypeTls, "Negotiated ALPN = %v", st.NextProto)
				// TODO(ekr@rtfm.com): Abort on ALPN mismatch when others do.
				if st.NextProto != kQuicALPNToken {
					logf(logTypeTls, "ALPN mismatch %v != %v", st.NextProto, kQuicALPNToken)
				}
				cs := st.CipherSuite
				c.cs = &cs
				c.finished = true

				break outer
			}
			// Loop
		case mint.AlertWouldBlock:
			logf(logTypeTls, "TLS would have blocked")
			break outer
		default:
			return nil, fmt.Errorf("TLS sent an alert %v", alert)
		}
	}

	logf(logTypeTls, "TLS wrote %d bytes", c.conn.OutputLen())

	return c.conn.getOutput(), nil
}

func (c *tlsConn) readPostHandshake(input []byte) error {
	// TODO(ekr@rtfm.com): Fix this
	/*
		logf(logTypeTls, "TLS post-handshake input len=%v", len(input))
		if input != nil {
			err := c.conn.input(input)
			if err != nil {
				return err
			}
		}

		buf := make([]byte, 1)
		n, err := c.tls.Read(buf)
		if n != 0 {
			return fmt.Errorf("Received TLS application data")
		}
		if err != mint.AlertWouldBlock || err == mint.WouldBlock {
			return err
		}*/
	return nil
}

func (c *tlsConn) computeExporter(label string) ([]byte, error) {
	return c.tls.ComputeExporter(label, []byte{}, c.cs.Hash.Size())
}

func (c *tlsConn) getHsState() string {
	return c.tls.GetHsState().String()
}
