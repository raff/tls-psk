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
=========
Refer the example directory for [client](https://github.com/bpatel85/tls-psk/tree/master/example/client/go) and [server](https://github.com/bpatel85/tls-psk/tree/master/example/server) usage.


