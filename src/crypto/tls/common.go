// TINYGO: The following is copied and modified from Go 1.19.3 official implementation.

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"hash"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// CurveID is the type of a TLS identifier for an elliptic curve. See
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8.
//
// In TLS 1.3, this type is called NamedGroup, but at this time this library
// only supports Elliptic Curve based groups. See RFC 8446, Section 4.2.7.
type CurveID uint16

// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
	// Version is the TLS version used by the connection (e.g. VersionTLS12).
	Version uint16

	// HandshakeComplete is true if the handshake has concluded.
	HandshakeComplete bool

	// DidResume is true if this connection was successfully resumed from a
	// previous session with a session ticket or similar mechanism.
	DidResume bool

	// CipherSuite is the cipher suite negotiated for the connection (e.g.
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_AES_128_GCM_SHA256).
	CipherSuite uint16

	// NegotiatedProtocol is the application protocol negotiated with ALPN.
	NegotiatedProtocol string

	// NegotiatedProtocolIsMutual used to indicate a mutual NPN negotiation.
	//
	// Deprecated: this value is always true.
	NegotiatedProtocolIsMutual bool

	// ServerName is the value of the Server Name Indication extension sent by
	// the client. It's available both on the server and on the client side.
	ServerName string

	// PeerCertificates are the parsed certificates sent by the peer, in the
	// order in which they were sent. The first element is the leaf certificate
	// that the connection is verified against.
	//
	// On the client side, it can't be empty. On the server side, it can be
	// empty if Config.ClientAuth is not RequireAnyClientCert or
	// RequireAndVerifyClientCert.
	//
	// PeerCertificates and its contents should not be modified.
	PeerCertificates []*x509.Certificate

	// VerifiedChains is a list of one or more chains where the first element is
	// PeerCertificates[0] and the last element is from Config.RootCAs (on the
	// client side) or Config.ClientCAs (on the server side).
	//
	// On the client side, it's set if Config.InsecureSkipVerify is false. On
	// the server side, it's set if Config.ClientAuth is VerifyClientCertIfGiven
	// (and the peer provided a certificate) or RequireAndVerifyClientCert.
	//
	// VerifiedChains and its contents should not be modified.
	VerifiedChains [][]*x509.Certificate

	// SignedCertificateTimestamps is a list of SCTs provided by the peer
	// through the TLS handshake for the leaf certificate, if any.
	SignedCertificateTimestamps [][]byte

	// OCSPResponse is a stapled Online Certificate Status Protocol (OCSP)
	// response provided by the peer for the leaf certificate, if any.
	OCSPResponse []byte

	// TLSUnique contains the "tls-unique" channel binding value (see RFC 5929,
	// Section 3). This value will be nil for TLS 1.3 connections and for
	// resumed connections that don't support Extended Master Secret (RFC 7627).
	TLSUnique []byte

	// ekm is a closure exposed via ExportKeyingMaterial.
	ekm func(label string, context []byte, length int) ([]byte, error)
}

// ConnectionState returns basic TLS details about the connection.
func (c *Conn) ConnectionState() ConnectionState {
	panic("tinygo: unimplemented")
}

// NetConn returns the underlying connection that is wrapped by c.
// Note that writing to or reading from this connection directly will corrupt the
// TLS session.
func (c *Conn) NetConn() net.Conn {
	return c.conn
}

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

// ClientSessionCache is a cache of ClientSessionState objects that can be used
// by a client to resume a TLS session with a given server. ClientSessionCache
// implementations should expect to be called concurrently from different
// goroutines. Up to TLS 1.2, only ticket-based resumption is supported, not
// SessionID-based resumption. In TLS 1.3 they were merged into PSK modes, which
// are supported via this interface.
type ClientSessionCache interface {
	// Get searches for a ClientSessionState associated with the given key.
	// On return, ok is true if one was found.
	Get(sessionKey string) (session *ClientSessionState, ok bool)

	// Put adds the ClientSessionState to the cache with the given key. It might
	// get called multiple times in a connection if a TLS 1.3 server provides
	// more than one session ticket. If called with a nil *ClientSessionState,
	// it should remove the cache entry.
	Put(sessionKey string, cs *ClientSessionState)
}

//go:generate stringer -type=SignatureScheme,CurveID,ClientAuthType -output=common_string.go

// SignatureScheme identifies a signature algorithm supported by TLS. See
// RFC 8446, Section 4.2.3.
type SignatureScheme uint16

// ClientHelloInfo contains information from a ClientHello message in order to
// guide application logic in the GetCertificate and GetConfigForClient callbacks.
type ClientHelloInfo struct {
	// CipherSuites lists the CipherSuites supported by the client (e.g.
	// TLS_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).
	CipherSuites []uint16

	// ServerName indicates the name of the server requested by the client
	// in order to support virtual hosting. ServerName is only set if the
	// client is using SNI (see RFC 4366, Section 3.1).
	ServerName string

	// SupportedCurves lists the elliptic curves supported by the client.
	// SupportedCurves is set only if the Supported Elliptic Curves
	// Extension is being used (see RFC 4492, Section 5.1.1).
	SupportedCurves []CurveID

	// SupportedPoints lists the point formats supported by the client.
	// SupportedPoints is set only if the Supported Point Formats Extension
	// is being used (see RFC 4492, Section 5.1.2).
	SupportedPoints []uint8

	// SignatureSchemes lists the signature and hash schemes that the client
	// is willing to verify. SignatureSchemes is set only if the Signature
	// Algorithms Extension is being used (see RFC 5246, Section 7.4.1.4.1).
	SignatureSchemes []SignatureScheme

	// SupportedProtos lists the application protocols supported by the client.
	// SupportedProtos is set only if the Application-Layer Protocol
	// Negotiation Extension is being used (see RFC 7301, Section 3.1).
	//
	// Servers can select a protocol by setting Config.NextProtos in a
	// GetConfigForClient return value.
	SupportedProtos []string

	// SupportedVersions lists the TLS versions supported by the client.
	// For TLS versions less than 1.3, this is extrapolated from the max
	// version advertised by the client, so values other than the greatest
	// might be rejected if used.
	SupportedVersions []uint16

	// Conn is the underlying net.Conn for the connection. Do not read
	// from, or write to, this connection; that will cause the TLS
	// connection to fail.
	Conn net.Conn

	// config is embedded by the GetCertificate or GetConfigForClient caller,
	// for use with SupportsCertificate.
	config *Config

	// ctx is the context of the handshake that is in progress.
	ctx context.Context
}

// CertificateRequestInfo contains information from a server's
// CertificateRequest message, which is used to demand a certificate and proof
// of control from a client.
type CertificateRequestInfo struct {
	// AcceptableCAs contains zero or more, DER-encoded, X.501
	// Distinguished Names. These are the names of root or intermediate CAs
	// that the server wishes the returned certificate to be signed by. An
	// empty slice indicates that the server has no preference.
	AcceptableCAs [][]byte

	// SignatureSchemes lists the signature schemes that the server is
	// willing to verify.
	SignatureSchemes []SignatureScheme

	// Version is the TLS version that was negotiated for this connection.
	Version uint16

	// ctx is the context of the handshake that is in progress.
	ctx context.Context
}

// RenegotiationSupport enumerates the different levels of support for TLS
// renegotiation. TLS renegotiation is the act of performing subsequent
// handshakes on a connection after the first. This significantly complicates
// the state machine and has been the source of numerous, subtle security
// issues. Initiating a renegotiation is not supported, but support for
// accepting renegotiation requests may be enabled.
//
// Even when enabled, the server may not change its identity between handshakes
// (i.e. the leaf certificate must be the same). Additionally, concurrent
// handshake and application data flow is not permitted so renegotiation can
// only be used with protocols that synchronise with the renegotiation, such as
// HTTPS.
//
// Renegotiation is not defined in TLS 1.3.
type RenegotiationSupport int

// A Config structure is used to configure a TLS client or server.
// After one has been passed to a TLS function it must not be
// modified. A Config may be reused; the tls package will also not
// modify it.
type Config struct {
	// Rand provides the source of entropy for nonces and RSA blinding.
	// If Rand is nil, TLS uses the cryptographic random reader in package
	// crypto/rand.
	// The Reader must be safe for use by multiple goroutines.
	Rand io.Reader

	// Time returns the current time as the number of seconds since the epoch.
	// If Time is nil, TLS uses time.Now.
	Time func() time.Time

	// Certificates contains one or more certificate chains to present to the
	// other side of the connection. The first certificate compatible with the
	// peer's requirements is selected automatically.
	//
	// Server configurations must set one of Certificates, GetCertificate or
	// GetConfigForClient. Clients doing client-authentication may set either
	// Certificates or GetClientCertificate.
	//
	// Note: if there are multiple Certificates, and they don't have the
	// optional field Leaf set, certificate selection will incur a significant
	// per-handshake performance cost.
	Certificates []Certificate

	// NameToCertificate maps from a certificate name to an element of
	// Certificates. Note that a certificate name can be of the form
	// '*.example.com' and so doesn't have to be a domain name as such.
	//
	// Deprecated: NameToCertificate only allows associating a single
	// certificate with a given name. Leave this field nil to let the library
	// select the first compatible chain from Certificates.
	NameToCertificate map[string]*Certificate

	// GetCertificate returns a Certificate based on the given
	// ClientHelloInfo. It will only be called if the client supplies SNI
	// information or if Certificates is empty.
	//
	// If GetCertificate is nil or returns nil, then the certificate is
	// retrieved from NameToCertificate. If NameToCertificate is nil, the
	// best element of Certificates will be used.
	//
	// Once a Certificate is returned it should not be modified.
	GetCertificate func(*ClientHelloInfo) (*Certificate, error)

	// GetClientCertificate, if not nil, is called when a server requests a
	// certificate from a client. If set, the contents of Certificates will
	// be ignored.
	//
	// If GetClientCertificate returns an error, the handshake will be
	// aborted and that error will be returned. Otherwise
	// GetClientCertificate must return a non-nil Certificate. If
	// Certificate.Certificate is empty then no certificate will be sent to
	// the server. If this is unacceptable to the server then it may abort
	// the handshake.
	//
	// GetClientCertificate may be called multiple times for the same
	// connection if renegotiation occurs or if TLS 1.3 is in use.
	//
	// Once a Certificate is returned it should not be modified.
	GetClientCertificate func(*CertificateRequestInfo) (*Certificate, error)

	// GetConfigForClient, if not nil, is called after a ClientHello is
	// received from a client. It may return a non-nil Config in order to
	// change the Config that will be used to handle this connection. If
	// the returned Config is nil, the original Config will be used. The
	// Config returned by this callback may not be subsequently modified.
	//
	// If GetConfigForClient is nil, the Config passed to Server() will be
	// used for all connections.
	//
	// If SessionTicketKey was explicitly set on the returned Config, or if
	// SetSessionTicketKeys was called on the returned Config, those keys will
	// be used. Otherwise, the original Config keys will be used (and possibly
	// rotated if they are automatically managed).
	GetConfigForClient func(*ClientHelloInfo) (*Config, error)

	// VerifyPeerCertificate, if not nil, is called after normal
	// certificate verification by either a TLS client or server. It
	// receives the raw ASN.1 certificates provided by the peer and also
	// any verified chains that normal processing found. If it returns a
	// non-nil error, the handshake is aborted and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. If normal verification is disabled (on the
	// client when InsecureSkipVerify is set, or on a server when ClientAuth is
	// RequestClientCert or RequireAnyClientCert), then this callback will be
	// considered but the verifiedChains argument will always be nil. When
	// ClientAuth is NoClientCert, this callback is not called on the server.
	// rawCerts may be empty on the server if ClientAuth is RequestClientCert or
	// VerifyClientCertIfGiven.
	//
	// This callback is not invoked on resumed connections, as certificates are
	// not re-verified on resumption.
	//
	// verifiedChains and its contents should not be modified.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyConnection, if not nil, is called after normal certificate
	// verification and after VerifyPeerCertificate by either a TLS client
	// or server. If it returns a non-nil error, the handshake is aborted
	// and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. This callback will run for all connections,
	// including resumptions, regardless of InsecureSkipVerify or ClientAuth
	// settings.
	VerifyConnection func(ConnectionState) error

	// RootCAs defines the set of root certificate authorities
	// that clients use when verifying server certificates.
	// If RootCAs is nil, TLS uses the host's root CA set.
	RootCAs *x509.CertPool

	// NextProtos is a list of supported application level protocols, in
	// order of preference. If both peers support ALPN, the selected
	// protocol will be one from this list, and the connection will fail
	// if there is no mutually supported protocol. If NextProtos is empty
	// or the peer doesn't support ALPN, the connection will succeed and
	// ConnectionState.NegotiatedProtocol will be empty.
	NextProtos []string

	// ServerName is used to verify the hostname on the returned
	// certificates unless InsecureSkipVerify is given. It is also included
	// in the client's handshake to support virtual hosting unless it is
	// an IP address.
	ServerName string

	// ClientAuth determines the server's policy for
	// TLS Client Authentication. The default is NoClientCert.
	ClientAuth ClientAuthType

	// ClientCAs defines the set of root certificate authorities
	// that servers use if required to verify a client certificate
	// by the policy in ClientAuth.
	ClientCAs *x509.CertPool

	// InsecureSkipVerify controls whether a client verifies the server's
	// certificate chain and host name. If InsecureSkipVerify is true, crypto/tls
	// accepts any certificate presented by the server and any host name in that
	// certificate. In this mode, TLS is susceptible to machine-in-the-middle
	// attacks unless custom verification is used. This should be used only for
	// testing or in combination with VerifyConnection or VerifyPeerCertificate.
	InsecureSkipVerify bool

	// CipherSuites is a list of enabled TLS 1.0–1.2 cipher suites. The order of
	// the list is ignored. Note that TLS 1.3 ciphersuites are not configurable.
	//
	// If CipherSuites is nil, a safe default list is used. The default cipher
	// suites might change over time.
	CipherSuites []uint16

	// PreferServerCipherSuites is a legacy field and has no effect.
	//
	// It used to control whether the server would follow the client's or the
	// server's preference. Servers now select the best mutually supported
	// cipher suite based on logic that takes into account inferred client
	// hardware, server hardware, and security.
	//
	// Deprecated: PreferServerCipherSuites is ignored.
	PreferServerCipherSuites bool

	// SessionTicketsDisabled may be set to true to disable session ticket and
	// PSK (resumption) support. Note that on clients, session ticket support is
	// also disabled if ClientSessionCache is nil.
	SessionTicketsDisabled bool

	// SessionTicketKey is used by TLS servers to provide session resumption.
	// See RFC 5077 and the PSK mode of RFC 8446. If zero, it will be filled
	// with random data before the first server handshake.
	//
	// Deprecated: if this field is left at zero, session ticket keys will be
	// automatically rotated every day and dropped after seven days. For
	// customizing the rotation schedule or synchronizing servers that are
	// terminating connections for the same host, use SetSessionTicketKeys.
	SessionTicketKey [32]byte

	// ClientSessionCache is a cache of ClientSessionState entries for TLS
	// session resumption. It is only used by clients.
	ClientSessionCache ClientSessionCache

	// UnwrapSession is called on the server to turn a ticket/identity
	// previously produced by [WrapSession] into a usable session.
	//
	// UnwrapSession will usually either decrypt a session state in the ticket
	// (for example with [Config.EncryptTicket]), or use the ticket as a handle
	// to recover a previously stored state. It must use [ParseSessionState] to
	// deserialize the session state.
	//
	// If UnwrapSession returns an error, the connection is terminated. If it
	// returns (nil, nil), the session is ignored. crypto/tls may still choose
	// not to resume the returned session.
	UnwrapSession func(identity []byte, cs ConnectionState) (*SessionState, error)

	// WrapSession is called on the server to produce a session ticket/identity.
	//
	// WrapSession must serialize the session state with [SessionState.Bytes].
	// It may then encrypt the serialized state (for example with
	// [Config.DecryptTicket]) and use it as the ticket, or store the state and
	// return a handle for it.
	//
	// If WrapSession returns an error, the connection is terminated.
	//
	// Warning: the return value will be exposed on the wire and to clients in
	// plaintext. The application is in charge of encrypting and authenticating
	// it (and rotating keys) or returning high-entropy identifiers. Failing to
	// do so correctly can compromise current, previous, and future connections
	// depending on the protocol version.
	WrapSession func(ConnectionState, *SessionState) ([]byte, error)

	// MinVersion contains the minimum TLS version that is acceptable.
	//
	// By default, TLS 1.2 is currently used as the minimum when acting as a
	// client, and TLS 1.0 when acting as a server. TLS 1.0 is the minimum
	// supported by this package, both as a client and as a server.
	//
	// The client-side default can temporarily be reverted to TLS 1.0 by
	// including the value "x509sha1=1" in the GODEBUG environment variable.
	// Note that this option will be removed in Go 1.19 (but it will still be
	// possible to set this field to VersionTLS10 explicitly).
	MinVersion uint16

	// MaxVersion contains the maximum TLS version that is acceptable.
	//
	// By default, the maximum version supported by this package is used,
	// which is currently TLS 1.3.
	MaxVersion uint16

	// CurvePreferences contains the elliptic curves that will be used in
	// an ECDHE handshake, in preference order. If empty, the default will
	// be used. The client will use the first preference as the type for
	// its key share in TLS 1.3. This may change in the future.
	CurvePreferences []CurveID

	// DynamicRecordSizingDisabled disables adaptive sizing of TLS records.
	// When true, the largest possible TLS record size is always used. When
	// false, the size of TLS records may be adjusted in an attempt to
	// improve latency.
	DynamicRecordSizingDisabled bool

	// Renegotiation controls what types of renegotiation are supported.
	// The default, none, is correct for the vast majority of applications.
	Renegotiation RenegotiationSupport

	// KeyLogWriter optionally specifies a destination for TLS master secrets
	// in NSS key log format that can be used to allow external programs
	// such as Wireshark to decrypt TLS connections.
	// See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format.
	// Use of KeyLogWriter compromises security and should only be
	// used for debugging.
	KeyLogWriter io.Writer

	// mutex protects sessionTicketKeys and autoSessionTicketKeys.
	mutex sync.RWMutex
	// sessionTicketKeys contains zero or more ticket keys. If set, it means
	// the keys were set with SessionTicketKey or SetSessionTicketKeys. The
	// first key is used for new tickets and any subsequent keys can be used to
	// decrypt old tickets. The slice contents are not protected by the mutex
	// and are immutable.
	sessionTicketKeys []ticketKey
	// autoSessionTicketKeys is like sessionTicketKeys but is owned by the
	// auto-rotation logic. See Config.ticketKeys.
	autoSessionTicketKeys []ticketKey
}

// Clone returns a shallow clone of c or nil if c is nil. It is safe to clone a [Config] that is
// being used concurrently by a TLS client or server.
func (c *Config) Clone() *Config {
	panic("tls: Config.Clone not implemented")
}

// ticketKey is the internal representation of a session ticket key.
type ticketKey struct {
	aesKey  [16]byte
	hmacKey [16]byte
	// created is the time at which this ticket key was created. See Config.ticketKeys.
	created time.Time
}

// A Certificate is a chain of one or more certificates, leaf first.
type Certificate struct {
	Certificate [][]byte
	// PrivateKey contains the private key corresponding to the public key in
	// Leaf. This must implement crypto.Signer with an RSA, ECDSA or Ed25519 PublicKey.
	// For a server up to TLS 1.2, it can also implement crypto.Decrypter with
	// an RSA PublicKey.
	PrivateKey crypto.PrivateKey
	// SupportedSignatureAlgorithms is an optional list restricting what
	// signature algorithms the PrivateKey can be used for.
	SupportedSignatureAlgorithms []SignatureScheme
	// OCSPStaple contains an optional OCSP response which will be served
	// to clients that request it.
	OCSPStaple []byte
	// SignedCertificateTimestamps contains an optional list of Signed
	// Certificate Timestamps which will be served to clients that request it.
	SignedCertificateTimestamps [][]byte
	// Leaf is the parsed form of the leaf certificate, which may be initialized
	// using x509.ParseCertificate to reduce per-handshake processing. If nil,
	// the leaf certificate will be parsed as needed.
	Leaf *x509.Certificate
}

// A QUICEventKind is a type of operation on a QUIC connection.
type QUICEventKind int

// QUICEncryptionLevel represents a QUIC encryption level used to transmit
// handshake messages.
type QUICEncryptionLevel int

// A QUICEvent is an event occurring on a QUIC connection.
//
// The type of event is specified by the Kind field.
// The contents of the other fields are kind-specific.
type QUICEvent struct {
	Kind QUICEventKind

	// Set for QUICSetReadSecret, QUICSetWriteSecret, and QUICWriteData.
	Level QUICEncryptionLevel

	// Set for QUICTransportParameters, QUICSetReadSecret, QUICSetWriteSecret, and QUICWriteData.
	// The contents are owned by crypto/tls, and are valid until the next NextEvent call.
	Data []byte

	// Set for QUICSetReadSecret and QUICSetWriteSecret.
	Suite uint16
}

type quicState struct {
	events    []QUICEvent
	nextEvent int

	// eventArr is a statically allocated event array, large enough to handle
	// the usual maximum number of events resulting from a single call: transport
	// parameters, Initial data, Early read secret, Handshake write and read
	// secrets, Handshake data, Application write secret, Application data.
	eventArr [8]QUICEvent

	started  bool
	signalc  chan struct{}   // handshake data is available to be read
	blockedc chan struct{}   // handshake is waiting for data, closed when done
	cancelc  <-chan struct{} // handshake has been canceled
	cancel   context.CancelFunc

	// readbuf is shared between HandleData and the handshake goroutine.
	// HandshakeCryptoData passes ownership to the handshake goroutine by
	// reading from signalc, and reclaims ownership by reading from blockedc.
	readbuf []byte

	transportParams []byte // to send to the peer
}

// activeCert is a handle to a certificate held in the cache. Once there are
// no alive activeCerts for a given certificate, the certificate is removed
// from the cache by a finalizer.
type activeCert struct {
	cert *x509.Certificate
}

// A halfConn represents one direction of the record layer
// connection, either sending or receiving.
type halfConn struct {
	sync.Mutex

	err     error  // first permanent error
	version uint16 // protocol version
	cipher  any    // cipher algorithm
	mac     hash.Hash
	seq     [8]byte // 64-bit sequence number

	scratchBuf [13]byte // to avoid allocs; interface method args escape

	nextCipher any       // next encryption state
	nextMac    hash.Hash // next MAC algorithm

	level         QUICEncryptionLevel // current QUIC encryption level
	trafficSecret []byte              // current TLS 1.3 traffic secret
}

// A Conn represents a secured connection.
// It implements the net.Conn interface.
type Conn struct {
	// constant
	conn        net.Conn
	isClient    bool
	handshakeFn func(context.Context) error // (*Conn).clientHandshake or serverHandshake
	quic        *quicState                  // nil for non-QUIC connections

	// isHandshakeComplete is true if the connection is currently transferring
	// application data (i.e. is not currently processing a handshake).
	// isHandshakeComplete is true implies handshakeErr == nil.
	isHandshakeComplete atomic.Bool
	// constant after handshake; protected by handshakeMutex
	handshakeMutex sync.Mutex
	handshakeErr   error   // error resulting from handshake
	vers           uint16  // TLS version
	haveVers       bool    // version has been negotiated
	config         *Config // configuration passed to constructor
	// handshakes counts the number of handshakes performed on the
	// connection so far. If renegotiation is disabled then this is either
	// zero or one.
	handshakes       int
	extMasterSecret  bool
	didResume        bool // whether this connection was a session resumption
	cipherSuite      uint16
	ocspResponse     []byte   // stapled OCSP response
	scts             [][]byte // signed certificate timestamps from server
	peerCertificates []*x509.Certificate
	// activeCertHandles contains the cache handles to certificates in
	// peerCertificates that are used to track active references.
	activeCertHandles []*activeCert
	// verifiedChains contains the certificate chains that we built, as
	// opposed to the ones presented by the server.
	verifiedChains [][]*x509.Certificate
	// serverName contains the server name indicated by the client, if any.
	serverName string
	// secureRenegotiation is true if the server echoed the secure
	// renegotiation extension. (This is meaningless as a server because
	// renegotiation is not supported in that case.)
	secureRenegotiation bool
	// ekm is a closure for exporting keying material.
	ekm func(label string, context []byte, length int) ([]byte, error)
	// resumptionSecret is the resumption_master_secret for handling
	// or sending NewSessionTicket messages.
	resumptionSecret []byte

	// ticketKeys is the set of active session ticket keys for this
	// connection. The first one is used to encrypt new tickets and
	// all are tried to decrypt tickets.
	ticketKeys []ticketKey

	// clientFinishedIsFirst is true if the client sent the first Finished
	// message during the most recent handshake. This is recorded because
	// the first transmitted Finished message is the tls-unique
	// channel-binding value.
	clientFinishedIsFirst bool

	// closeNotifyErr is any error from sending the alertCloseNotify record.
	closeNotifyErr error
	// closeNotifySent is true if the Conn attempted to send an
	// alertCloseNotify record.
	closeNotifySent bool

	// clientFinished and serverFinished contain the Finished message sent
	// by the client or server in the most recent handshake. This is
	// retained to support the renegotiation extension and tls-unique
	// channel-binding.
	clientFinished [12]byte
	serverFinished [12]byte

	// clientProtocol is the negotiated ALPN protocol.
	clientProtocol string

	// input/output
	in, out   halfConn
	rawInput  bytes.Buffer // raw input, starting with a record header
	input     bytes.Reader // application data waiting to be read, from rawInput.Next
	hand      bytes.Buffer // handshake data waiting to be read
	buffering bool         // whether records are buffered in sendBuf
	sendBuf   []byte       // a buffer of records waiting to be sent

	// bytesSent counts the bytes of application data sent.
	// packetsSent counts packets.
	bytesSent   int64
	packetsSent int64

	// retryCount counts the number of consecutive non-advancing records
	// received by Conn.readRecord. That is, records that neither advance the
	// handshake, nor deliver application data. Protected by in.Mutex.
	retryCount int

	// activeCall indicates whether Close has been call in the low bit.
	// the rest of the bits are the number of goroutines in Conn.Write.
	activeCall atomic.Int32

	tmp [16]byte
}

// Close closes the connection.
func (c *Conn) Close() error {
	return errors.New("tls: Conn.Close not implemented")
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// Read reads data from the connection.
//
// As Read calls [Conn.Handshake], in order to prevent indefinite blocking a deadline
// must be set for both Read and [Conn.Write] before Read is called when the handshake
// has not yet completed. See [Conn.SetDeadline], [Conn.SetReadDeadline], and
// [Conn.SetWriteDeadline].
func (c *Conn) Read(b []byte) (int, error) {
	return 0, errors.New("tls: Conn.Read not implemented")
}

// Write writes data to the connection.
//
// As Write calls [Conn.Handshake], in order to prevent indefinite blocking a deadline
// must be set for both [Conn.Read] and Write before Write is called when the handshake
// has not yet completed. See [Conn.SetDeadline], [Conn.SetReadDeadline], and
// [Conn.SetWriteDeadline].
func (c *Conn) Write(b []byte) (int, error) {
	return 0, errors.New("tls: Conn.Write not implemented")
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// A zero value for t means [Conn.Read] and [Conn.Write] will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means [Conn.Read] will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means [Conn.Write] will not time out.
// After a [Conn.Write] has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304

	// Deprecated: SSLv3 is cryptographically broken, and is no longer
	// supported by this package. See golang.org/issue/32716.
	VersionSSL30 = 0x0300
)

// A list of cipher suite IDs that are, or have been, implemented by this
// package.
//
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
const (
	// TLS 1.0 - 1.2 cipher suites.
	TLS_RSA_WITH_RC4_128_SHA                      uint16 = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                 uint16 = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA                  uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA                  uint16 = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256               uint16 = 0x003c
	TLS_RSA_WITH_AES_128_GCM_SHA256               uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384               uint16 = 0x009d
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              uint16 = 0xc007
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          uint16 = 0xc00a
	TLS_ECDHE_RSA_WITH_RC4_128_SHA                uint16 = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            uint16 = 0xc014
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       uint16 = 0xc023
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         uint16 = 0xc027
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       uint16 = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       uint16 = 0xc02c
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   uint16 = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xcca9

	// TLS 1.3 cipher suites.
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See RFC 7507.
	TLS_FALLBACK_SCSV uint16 = 0x5600

	// Legacy names for the corresponding cipher suites with the correct _SHA256
	// suffix, retained for backward compatibility.
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305   = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
)
