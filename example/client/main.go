package main

import (
	"fmt"
	"io"
	"log"

	tlsExt "github.com/bpatel85/tls-ext"
	psk "github.com/bpatel85/tls-psk"
)

// define GetKey and GetIdentity methods
func getIdentity() string {
	return "clientId"
}

func getKey(id string) ([]byte, error) {
	return []byte("secret"), nil
}

const serverPort int = 5000

func main() {
	config := &tlsExt.Config{
		CipherSuites: []uint16{psk.TLS_PSK_WITH_AES_128_CBC_SHA},
		MaxVersion:   tlsExt.VersionTLS12, // REQUIRED FOR NOW
		Extra: psk.PSKConfig{
			GetKey:      getKey,
			GetIdentity: getIdentity,
		},
		InsecureSkipVerify: true,
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

	message := "Hello\n"
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
