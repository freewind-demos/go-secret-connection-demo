package main

import (
	"net"
	"github.com/golang-demos/go-secret-connection-demo/secret"
)

func main() {
	privateKey, publicKey := secret.GenerateMyKeys()

	listener, _ := net.Listen("tcp", "localhost:9999")
	defer listener.Close()

	conn, _ := listener.Accept()

	secret.SecretTransfer(conn, privateKey, publicKey)
}
