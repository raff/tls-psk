package main

import (
	"fmt"
	"io"
	"log"

	tlsExt "github.com/bpatel85/tls-ext"
	psk "github.com/bpatel85/tls-psk"
)

const serverPort int = 5000

type ClientAuthProvider struct {
}

// client-only - returns the client identity
func (svr ClientAuthProvider) GetIdentity() string {
	return "clientId"
}

// for client - returns the key for this client
func (svr ClientAuthProvider) GetKey(identity string) ([]byte, error) {
	return []byte("secret"), nil
}

func main() {
	config := &tlsExt.Config{
		CipherSuites:             []uint16{psk.TLS_PSK_WITH_AES_128_CBC_SHA},
		PreferServerCipherSuites: false,
		MaxVersion:               tlsExt.VersionTLS12, // REQUIRED FOR NOW
		Extra:                    ClientAuthProvider{},
		InsecureSkipVerify:       true,
	}

	conn, err := tlsExt.Dial("tcp", fmt.Sprintf(":%d", serverPort), config)
	if err != nil {
		log.Fatalf("client: failed to dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())

	state := conn.ConnectionState()
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)

	message := "Hello"
	n, err := io.WriteString(conn, message)
	if err != nil {
		log.Fatalf("client: write: %s", err)
	}
	log.Printf("client: wrote %q (%d bytes)", message, n)

	reply := make([]byte, 256)
	n, err = conn.Read(reply)
	if err != nil {
		log.Fatalf("client: read error: %s", err)
	}

	log.Printf("client: read %q (%d bytes)", string(reply[:n]), n)
	log.Print("client: exiting")
}
