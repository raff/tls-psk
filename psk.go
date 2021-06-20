// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package psk

import (
	"crypto/x509"
	"errors"
	"fmt"

	tlsext "github.com/bpatel85/tls-ext"
)

func init() {
	tlsext.RegisterCipherSuites(pskCipherSuites...)
}

// The list of supported PSK cipher suites
var pskCipherSuites = []*tlsext.CipherSuiteImpl{
	{
		Id:     TLS_PSK_WITH_3DES_EDE_CBC_SHA,
		KeyLen: 24,
		MacLen: 20,
		IvLen:  8,
		KA:     pskKA,
		Flags:  tlsext.SuiteNoCerts,
		Cipher: tlsext.Cipher3DES,
		Mac:    tlsext.MacSHA1,
		Aead:   nil,
	},
	{
		Id:     TLS_PSK_WITH_AES_128_CBC_SHA,
		KeyLen: 16,
		MacLen: 20,
		IvLen:  16,
		KA:     pskKA,
		Flags:  tlsext.SuiteNoCerts,
		Cipher: tlsext.CipherAES,
		Mac:    tlsext.MacSHA1,
		Aead:   nil,
	},
	{
		Id:     TLS_PSK_WITH_3DES_EDE_CBC_SHA,
		KeyLen: 32,
		MacLen: 20,
		IvLen:  16,
		KA:     pskKA,
		Flags:  tlsext.SuiteNoCerts,
		Cipher: tlsext.CipherAES,
		Mac:    tlsext.MacSHA1,
		Aead:   nil,
	},
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

func pskKA(version uint16) tlsext.KeyAgreement {
	return pskKeyAgreement{}
}

// pskKeyAgreement implements the standard PSK TLS key agreement
type pskKeyAgreement struct {
}

func (ka pskKeyAgreement) GenerateServerKeyExchange(config *tlsext.Config, cert *tlsext.Certificate, clientHello *tlsext.ClientHelloMsg, hello *tlsext.ServerHelloMsg) (*tlsext.ServerKeyExchangeMsg, error) {
	// no server key exchange
	return nil, nil
}

func (ka pskKeyAgreement) ProcessClientKeyExchange(config *tlsext.Config, cert *tlsext.Certificate, ckx *tlsext.ClientKeyExchangeMsg, version uint16) ([]byte, error) {
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
	if version != tlsext.VersionSSL30 {
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

	pskLen := len(psk)

	preMasterSecret := make([]byte, 2*pskLen+4)
	preMasterSecret[0] = byte(pskLen >> 8)
	preMasterSecret[1] = byte(pskLen)
	preMasterSecret[pskLen+2] = preMasterSecret[0]
	preMasterSecret[pskLen+3] = preMasterSecret[1]
	copy(preMasterSecret[pskLen+4:], psk)

	return preMasterSecret, nil
}

func (ka pskKeyAgreement) ProcessServerKeyExchange(config *tlsext.Config, clientHello *tlsext.ClientHelloMsg, serverHello *tlsext.ServerHelloMsg, cert *x509.Certificate, skx *tlsext.ServerKeyExchangeMsg) error {
	return errors.New("unexpected ServerKeyExchange")
}

func (ka pskKeyAgreement) GenerateClientKeyExchange(config *tlsext.Config, clientHello *tlsext.ClientHelloMsg, cert *x509.Certificate) ([]byte, *tlsext.ClientKeyExchangeMsg, error) {

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
	pskLen := len(psk)

	preMasterSecret := make([]byte, 2*pskLen+4)
	preMasterSecret[0] = byte(pskLen >> 8)
	preMasterSecret[1] = byte(pskLen)
	preMasterSecret[pskLen+2] = preMasterSecret[0]
	preMasterSecret[pskLen+3] = preMasterSecret[1]
	copy(preMasterSecret[pskLen+4:], psk)

	bIdentity := []byte(pskIdentity)
	pskIdentityLen := len(bIdentity)

	ckx := new(tlsext.ClientKeyExchangeMsg)
	ckx.Ciphertext = make([]byte, pskIdentityLen+2)
	ckx.Ciphertext[0] = byte(pskIdentityLen >> 8)
	ckx.Ciphertext[1] = byte(pskIdentityLen)
	copy(ckx.Ciphertext[2:], bIdentity)

	return preMasterSecret, ckx, nil
}
