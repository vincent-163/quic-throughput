package main

import (
	"time"
	"net"
	"fmt"
	"crypto/tls"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"context"
	"io"
	"math/big"
	"sync/atomic"

	"github.com/lucas-clemente/quic-go"
)

type zeroReader struct{}
func (zeroReader) Read(p []byte) (int, error) {
	for i := range p { p[i] = 0 }
	return len(p), nil
}


type slowPacketConn struct {
        net.PacketConn
	latency time.Duration
}
func (s slowPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
        time.AfterFunc(s.latency, func() {
                s.PacketConn.WriteTo(p, addr)
        })
        return len(p), nil
}

// copied from echo example
// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}


func main() {
	ctx := context.Background()
	go serverMain(ctx)
	time.Sleep(time.Second)
	fmt.Println("starting client")
	clientMain(ctx, time.Millisecond*200)
}

func serverMain(ctx context.Context) {
	lis, err := quic.ListenAddr("127.0.0.1:3012", generateTLSConfig(), &quic.Config{
		MaxReceiveStreamFlowControlWindow: 64*1024*1024,
		MaxReceiveConnectionFlowControlWindow: 128*1024*1024,
	})
	if err != nil {
		panic(err)
	}
	defer lis.Close()
	sess, err := lis.Accept(ctx)
	if err != nil {
		panic(err)
	}
	defer sess.Close()
	st, err := sess.AcceptStream(ctx)
	if err != nil {
		panic(err)
	}
	defer st.Close()
	io.Copy(st, io.LimitReader(zeroReader{}, 1024*1024*500))
}

func clientMain(ctx context.Context, latency time.Duration) {
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		panic(err)
	}
	slowConn := slowPacketConn{udpConn, latency}
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	sess, err := quic.DialContext(ctx, slowConn, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3012}, "", tlsConf, nil)
	if err != nil {
		panic(err)
	}
	defer sess.Close()
	st, err := sess.OpenStream()
	if err != nil {
		panic(err)
	}
	if _, err := st.Write([]byte("hello")); err != nil {
		panic(err)
	}
	// test for 10 seconds
	ctx2, cancel := context.WithTimeout(ctx, time.Second * 30)
	defer cancel()
	var counter int64
	go func() {
		var lastCounter int64 = 0
		for {
			select {
			case <-ctx2.Done():
				return
			case <-time.After(time.Second):
				curCounter := atomic.LoadInt64(&counter)
				fmt.Printf("%d bytes per second\n", curCounter-lastCounter)
				lastCounter = curCounter
			}
		}
	}()
	buf := make([]byte, 32768)
	loop:
	for {
		select {
		case <-ctx2.Done():
			break loop
		default:
		}
		n, err := st.Read(buf)
		if err != nil {
			panic(err)
		}
		atomic.AddInt64(&counter, int64(n))
	}
}
