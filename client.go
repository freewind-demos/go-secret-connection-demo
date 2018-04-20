package main

import (
	"net"
	"github.com/golang-demos/go-secret-connection-demo/secret"
)

func main() {
	privateKey, publicKey := secret.GenerateMyKeys()
	conn, _ := net.Dial("tcp", "localhost:9999")
	secret.SecretTransfer(conn, privateKey, publicKey)
}
