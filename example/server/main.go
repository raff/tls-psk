package main

import (
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/bpatel85/tls-ext"
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
	config := &tls.Config{
		CipherSuites:             []uint16{psk.TLS_PSK_WITH_AES_128_CBC_SHA},
		PreferServerCipherSuites: false,
		Certificates:             []tls.Certificate{{}}, // pass in empty configs
		MaxVersion:               tls.VersionTLS12,      // REQUIRED FOR NOW
		Extra: psk.PSKConfig{
			GetKey:      getKey,
			GetIdentity: getIdentity,
		},
	}

	// start the server
	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", serverPort), config)
	if err != nil {
		panic(err)
	}

	log.Print("server: listening")
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		defer conn.Close()
		log.Printf("server: accepted from %s", conn.RemoteAddr())
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			log.Print("ok=true")
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
			}
		}
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 512)
	for {
		log.Print("server: conn: waiting")
		n, err := conn.Read(buf)
		if err != nil {
			if err != nil && err != io.EOF {
				log.Printf("server: conn: failed to read: %s", err)
			}
			break
		}
		log.Printf("server: conn: echo %q\n", string(buf[:n]))

		n, err = conn.Write(buf[:n])
		log.Printf("server: conn: wrote %d bytes", n)

		if err != nil {
			log.Printf("server: failed to write: %s", err)
			break
		}
	}
	log.Println("server: conn: closed")
}
