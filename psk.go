// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

type PSKConfigProvider interface {
	// client-only - returns the client identity
	GetIdentity() string

	// for server - returns the key associated to a client identity
	// for client - returns the key for this client
	GetKey(identity string) ([]byte, error)
}

var defaultPSKConfig Config = Config{
	CipherSuites: []uint16{TLS_PSK_WITH_AES_128_CBC_SHA},
	Certificates: []Certificate{Certificate{}},
}

// A suitable configuration for a TLS-PSK (only) session
func TLSPSKConfig() *Config {
	return &defaultPSKConfig
}
