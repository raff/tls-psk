tls-psk
=======

This package adds PSK cipher suites to the "standard" Go crypto/tls package.
Well, since currently the standard crypto/tls package is not extensible, this package uses an "extensible" version
(a copy of the standard crypto/tls package with some added functionalities)

This version is compatible with crypto/tls from Go 1.16.5. Refer release tags for other versions of this packages.

Installatation
==============

    > go get github.com/bpatel85/tls-psk

Usage
=====

    // import packages
    import (
        "github.com/bpatel85/tls-ext"
        "github.com/bpatel85/tls-psk"
    )
    
    // define GetKey and GetIdentity methods

    func getIdentity() string {
       return "clientid"
    }

    func getKey(id string) ([]byte, error) {
       return []byte("secret"), nil
    }

    // create the appropriate TLS configuration
    // note that we specifiy a single cipher suite of type TLS_PSK_*
    // also note that the "server" requires a certificate, even if not used here

    var (
        config := &tls.Config{
                CipherSuites: []uint16{psk.TLS_PSK_WITH_AES_128_CBC_SHA},
                Certificates: []tls.Certificate{tls.Certificate{}},
                MaxVersion: tls.VersionTLS12,   // <<<<<<<<<< REQUIRED FOR NOW
                Extra: psk.PSKConfig{
                    GetKey: getKey,
                    GetIdentity: getIdentity,
                    },
                }
    )

    // start the server
    listener, err := tls.Listen("tcp", port, config)

    // connect a client
    conn, err := tls.Dial("tcp", port, config)


