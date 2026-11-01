package native_dns_context_runtime_test

// Account-free inline ECH acceptance at the actual Core TLS boundary. This is
// TLS 1.3 over owned loopback sockets, not a VPN/QUIC-SNI or remote ECH-DNS test.
import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	coretls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/crypto/cryptobyte"
)

const echInnerName = "private-inner.fixture.invalid"
const echOuterName = "public-cover.fixture.invalid"

func echFixtureCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned inline ECH CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{echInnerName, echOuterName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	if err != nil {
		t.Fatal(err)
	}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

func echFixtureConfig(t *testing.T, public []byte) (config, list []byte) {
	t.Helper()
	var b cryptobyte.Builder
	b.AddUint16(0xfe0d)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(7)
		b.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(public) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0x0001) // HKDF-SHA256
			b.AddUint16(0x0001) // AES-128-GCM
		})
		b.AddUint8(0)
		b.AddUint8(uint8(len(echOuterName)))
		b.AddBytes([]byte(echOuterName))
		b.AddUint16(0) // no extensions
	})
	var err error
	config, err = b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var l cryptobyte.Builder
	l.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(config) })
	list, err = l.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return
}

type echPeerResult struct {
	state tls.ConnectionState
	bytes int
	err   error
}

func TestAcceptanceInlineECH(t *testing.T) {
	if !strings.EqualFold(os.Getenv("CI"), "true") || runtime.GOOS == "darwin" && !strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		t.Fatal("inline ECH runtime is CI-only")
	}
	for _, mode := range []string{"accepted", "wrong_key", "untrusted_root"} {
		if t.Run(mode, func(t *testing.T) { testAcceptanceInlineECH(t, mode) }) {
			t.Logf("INLINE_ECH_TLS13_PASS mode=%s", mode)
		}
	}
}

func testAcceptanceInlineECH(t *testing.T, mode string) {
	certificate, root := echFixtureCertificate(t)
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config, list := echFixtureConfig(t, private.PublicKey().Bytes())
	serverConfig := config
	serverPrivate := private.Bytes()
	if mode == "wrong_key" {
		other, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serverPrivate = other.Bytes()
		serverConfig, _ = echFixtureConfig(t, other.PublicKey().Bytes())
	}
	if mode == "untrusted_root" {
		_, root = echFixtureCertificate(t)
	}
	clientConfig := (&coretls.Config{ServerName: echInnerName, MinVersion: "1.3", MaxVersion: "1.3",
		DisableSystemRoot: true, Certificate: []*coretls.Certificate{{Certificate: root, Usage: coretls.Certificate_AUTHORITY_VERIFY}},
		EchConfigList: base64.StdEncoding.EncodeToString(list)}).GetTLSConfig()
	if !bytes.Equal(clientConfig.EncryptedClientHelloConfigList, list) || clientConfig.InsecureSkipVerify {
		t.Fatal("Core did not apply the exact inline ECH list with normal trust verification")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := listener.(*net.TCPListener).SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	nonce := []byte(fmt.Sprintf("owned-inline-ECH-%s-%x", mode, private.PublicKey().Bytes()[:8]))
	done := make(chan echPeerResult, 1)
	go func() {
		result := echPeerResult{}
		defer func() { done <- result }()
		raw, err := listener.Accept()
		if err != nil {
			result.err = err
			return
		}
		defer raw.Close()
		if err := raw.SetDeadline(deadline); err != nil {
			result.err = err
			return
		}
		peer := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate}, EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{
				Config: serverConfig, PrivateKey: serverPrivate, SendAsRetry: true}}})
		result.err = peer.Handshake()
		result.state = peer.ConnectionState()
		if result.err != nil || !result.state.ECHAccepted {
			return
		}
		payload := make([]byte, len(nonce))
		result.bytes, result.err = io.ReadFull(peer, payload)
		if result.err == nil && !bytes.Equal(payload, nonce) {
			result.err = errors.New("ECH application nonce changed")
		}
		if result.err == nil {
			_, result.err = peer.Write(payload)
		}
	}()
	var raw net.Conn
	defer func() {
		listener.Close()
		if raw != nil {
			raw.Close()
		}
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("owned inline ECH peer did not retire")
		}
	}()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	raw, err = (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	client := coretls.Client(raw, clientConfig).(*coretls.Conn)
	err = client.HandshakeContext(ctx)
	if mode == "wrong_key" {
		var rejected *tls.ECHRejectionError
		if !errors.As(err, &rejected) || client.ConnectionState().ECHAccepted {
			t.Fatalf("wrong ECH key was not rejected specifically as ECH: %v", err)
		}
	} else if mode == "untrusted_root" {
		var untrusted x509.UnknownAuthorityError
		if !errors.As(err, &untrusted) {
			t.Fatalf("ECH bypassed ordinary certificate verification: %v", err)
		}
	} else {
		if err != nil || !client.ConnectionState().ECHAccepted || client.ConnectionState().Version != tls.VersionTLS13 {
			t.Fatalf("Core inline ECH TLS 1.3 handshake failed: %v", err)
		}
		if _, err := client.Write(nonce); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(nonce))
		if _, err := io.ReadFull(client, response); err != nil || !bytes.Equal(response, nonce) {
			t.Fatalf("accepted ECH did not carry the exact application payload: %v", err)
		}
	}
	raw.Close()
	select {
	case result := <-done:
		done <- result // the deferred drain also proves the worker is done
		if mode == "accepted" {
			if result.err != nil || !result.state.ECHAccepted || result.state.ServerName != echInnerName || result.bytes != len(nonce) {
				t.Fatalf("server did not observe accepted inner name and nonce: %+v", result)
			}
		} else if result.bytes != 0 || mode == "wrong_key" && result.state.ECHAccepted {
			t.Fatalf("negative ECH control reached the application: %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("owned inline ECH peer did not complete")
	}
}
