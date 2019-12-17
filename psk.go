// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package psk

import (
	"crypto/x509"
	"errors"
        "fmt"
	"github.com/raff/tls-ext"
)

func init() {
	tls.RegisterCipherSuites(pskCipherSuites...)
}

// The list of supported PSK cipher suites
var pskCipherSuites = []*tls.CipherSuite{
	//tls.NewCipherSuite(TLS_PSK_WITH_RC4_128_SHA, 16, 20, 0, pskKA, tls.SuiteNoCerts, tls.CipherRC4, tls.MacSHA1, nil),
	tls.NewCipherSuite(TLS_PSK_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, pskKA, tls.SuiteNoCerts, tls.Cipher3DES, tls.MacSHA1, nil),
	tls.NewCipherSuite(TLS_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, pskKA, tls.SuiteNoCerts, tls.CipherAES, tls.MacSHA1, nil),
	tls.NewCipherSuite(TLS_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, pskKA, tls.SuiteNoCerts, tls.CipherAES, tls.MacSHA1, nil),
}

// A list of the possible PSK cipher suite ids.
// Note that not all of them are supported.
const (
	//TLS_PSK_WITH_RC4_128_SHA          uint16 = 0x008A
	TLS_PSK_WITH_3DES_EDE_CBC_SHA     uint16 = 0x008B
	TLS_PSK_WITH_AES_128_CBC_SHA      uint16 = 0x008C
	TLS_PSK_WITH_AES_256_CBC_SHA      uint16 = 0x008D
	TLS_DHE_PSK_WITH_RC4_128_SHA      uint16 = 0x008E
	TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA uint16 = 0x008F
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA  uint16 = 0x0090
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA  uint16 = 0x0091
	TLS_RSA_PSK_WITH_RC4_128_SHA      uint16 = 0x0092
	TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA uint16 = 0x0093
	TLS_RSA_PSK_WITH_AES_128_CBC_SHA  uint16 = 0x0094
	TLS_RSA_PSK_WITH_AES_256_CBC_SHA  uint16 = 0x0095
)

// Configuration for PSK cipher-suite. The client needs to provide a GetIdentity and GetKey functions to retrieve client id and pre-shared-key
type PSKConfig struct {
	// client-only - returns the client identity
	GetIdentity func() string

	// for server - returns the key associated to a client identity
	// for client - returns the key for this client
	GetKey func(identity string) ([]byte, error)
}

func pskKA(version uint16) tls.KeyAgreement {
	return pskKeyAgreement{}
}

// pskKeyAgreement implements the standard PSK TLS key agreement
type pskKeyAgreement struct {
}

func (ka pskKeyAgreement) GenerateServerKeyExchange(config *tls.Config, cert *tls.Certificate, clientHello *tls.ClientHelloMsg, hello *tls.ServerHelloMsg) (*tls.ServerKeyExchangeMsg, error) {
	// no server key exchange
	return nil, nil
}

func (ka pskKeyAgreement) ProcessClientKeyExchange(config *tls.Config, cert *tls.Certificate, ckx *tls.ClientKeyExchangeMsg, version uint16) ([]byte, error) {

	pskConfig, ok := config.Extra.(PSKConfig)
	if !ok {
		return nil, fmt.Errorf("bad Config - Extra not of type PSKConfig: %#v", config.Extra)
	}

	if pskConfig.GetKey == nil {
		return nil, errors.New("bad Config - GetKey required for PSK")
	}

	if len(ckx.Ciphertext) < 2 {
		return nil, errors.New("bad ClientKeyExchange")
	}

	ciphertext := ckx.Ciphertext
	if version != tls.VersionSSL30 {
		ciphertextLen := int(ckx.Ciphertext[0])<<8 | int(ckx.Ciphertext[1])
		if ciphertextLen != len(ckx.Ciphertext)-2 {
			return nil, errors.New("bad ClientKeyExchange")
		}
		ciphertext = ckx.Ciphertext[2:]
	}

	// ciphertext is actually the pskIdentity here
	psk, err := pskConfig.GetKey(string(ciphertext))
	if err != nil {
		return nil, err
	}

	lenpsk := len(psk)

	preMasterSecret := make([]byte, 2*lenpsk+4)
	preMasterSecret[0] = byte(lenpsk >> 8)
	preMasterSecret[1] = byte(lenpsk)
	preMasterSecret[lenpsk+2] = preMasterSecret[0]
	preMasterSecret[lenpsk+3] = preMasterSecret[1]
	copy(preMasterSecret[lenpsk+4:], psk)

	return preMasterSecret, nil
}

func (ka pskKeyAgreement) ProcessServerKeyExchange(config *tls.Config, clientHello *tls.ClientHelloMsg, serverHello *tls.ServerHelloMsg, cert *x509.Certificate, skx *tls.ServerKeyExchangeMsg) error {
	return errors.New("unexpected ServerKeyExchange")
}

func (ka pskKeyAgreement) GenerateClientKeyExchange(config *tls.Config, clientHello *tls.ClientHelloMsg, cert *x509.Certificate) ([]byte, *tls.ClientKeyExchangeMsg, error) {

	pskConfig, ok := config.Extra.(PSKConfig)
	if !ok {
		return nil, nil, fmt.Errorf("bad Config - Extra not of type PSKConfig: %#v", config.Extra)
	}

	if pskConfig.GetIdentity == nil {
		return nil, nil, errors.New("bad PSKConfig - GetIdentity required for PSK")
	}
	if pskConfig.GetKey == nil {
		return nil, nil, errors.New("bad PSKConfig - GetKey required for PSK")
	}

	pskIdentity := pskConfig.GetIdentity()
	key, err := pskConfig.GetKey(pskIdentity)
	if err != nil {
		return nil, nil, err
	}

	psk := []byte(key)
	lenpsk := len(psk)

	preMasterSecret := make([]byte, 2*lenpsk+4)
	preMasterSecret[0] = byte(lenpsk >> 8)
	preMasterSecret[1] = byte(lenpsk)
	preMasterSecret[lenpsk+2] = preMasterSecret[0]
	preMasterSecret[lenpsk+3] = preMasterSecret[1]
	copy(preMasterSecret[lenpsk+4:], psk)

	bIdentity := []byte(pskIdentity)
	lenpski := len(bIdentity)

	ckx := new(tls.ClientKeyExchangeMsg)
	ckx.Ciphertext = make([]byte, lenpski+2)
	ckx.Ciphertext[0] = byte(lenpski >> 8)
	ckx.Ciphertext[1] = byte(lenpski)
	copy(ckx.Ciphertext[2:], bIdentity)

	return preMasterSecret, ckx, nil
}
