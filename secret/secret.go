package secret

import (
	"golang.org/x/crypto/nacl/box"
	"crypto/rand"
	"github.com/golang-demos/go-utils-demo/goutils"
	"io"
	"net"
	"github.com/tendermint/go-crypto"
	"bytes"
	"golang.org/x/crypto/ripemd160"
	"crypto/sha256"
	"golang.org/x/crypto/nacl/secretbox"
	"encoding/binary"
	"fmt"
)

func GenerateMyKeys() (privateKey crypto.PrivKeyEd25519, publicKey crypto.PubKey) {
	privateKey = crypto.GenPrivKeyEd25519()
	publicKey = privateKey.PubKey()
	return
}

func SecretTransfer(conn net.Conn, privateKey crypto.PrivKeyEd25519, publicKey crypto.PubKey) {
	goutils.PrintlnByteArray("privateKey", privateKey.Bytes())
	goutils.PrintlnByteArray("publicKey", publicKey.Bytes())

	ephPublicKey, ephPrivateKey, _ := box.GenerateKey(rand.Reader)

	conn.Write(ephPublicKey[:])
	goutils.PrintlnByteArray("Send my ephPublicKey to peer", ephPublicKey[:])

	var remoteEphPubKey [32]byte
	io.ReadFull(conn, remoteEphPubKey[:])
	goutils.PrintlnByteArray("Received remote ephPublicKey from peer", remoteEphPubKey[:])

	var sharedSecret [32]byte
	computeSharedSecret(&sharedSecret, &remoteEphPubKey, ephPrivateKey)
	goutils.PrintlnByteArray("shared secret(should be the same to peer's)", sharedSecret[:])

	lowEphPubKey, highEphPubKey := sortKeys(ephPublicKey, &remoteEphPubKey)
	goutils.PrintlnByteArray("lowEphPubKey ", lowEphPubKey[:])
	goutils.PrintlnByteArray("highEphPubKey", highEphPubKey[:])

	receiveNonce, sendNonce := genNonces(lowEphPubKey, highEphPubKey, ephPublicKey == lowEphPubKey)
	goutils.PrintlnByteArray("receiveNonce", receiveNonce[:])
	goutils.PrintlnByteArray("sendNonce   ", sendNonce[:])

	challenge := genChallenge(lowEphPubKey, highEphPubKey)
	goutils.PrintlnByteArray("challenge", challenge[:])

	signature := signChallenge(challenge, privateKey)
	goutils.PrintlnByteArray("signature", signature.Bytes())

	authSignature := buildAuthSignature(publicKey, signature)
	goutils.PrintlnByteArray("authSignature", authSignature)

	sendAuthSignature(conn, authSignature, &sharedSecret, sendNonce)

	remotePublicKey, remoteSignature := readRemoteAuthSignature(conn, &sharedSecret, receiveNonce)
	goutils.PrintlnByteArray("remotePublicKey", remotePublicKey.Bytes())
	goutils.PrintlnByteArray("remoteSignature", remoteSignature.Bytes())

	ok := remotePublicKey.VerifyBytes(challenge[:], remoteSignature)
	if ok {
		fmt.Println("Verification is OK, we are in secret")
	} else {
		fmt.Println("Verification failed")
	}
}

func readRemoteAuthSignature(conn net.Conn, sharedSecret *[32]byte, receiveNonce *[24]byte) (remotePublicKey crypto.PubKey, remoteSignature crypto.Signature) {
	messageLength := readLength(conn)
	fmt.Println("read length of message: ", messageLength)

	authMessage := make([]byte, messageLength)
	io.ReadFull(conn, authMessage)
	goutils.PrintlnByteArray("read sealed message", authMessage)

	var out []byte
	out, _ = secretbox.Open(out[:], authMessage, receiveNonce, sharedSecret)
	goutils.PrintlnByteArray("message opened", out)

	remotePublicKeyBytes := out[:37]
	remoteSignatureBytes := out[37:]

	goutils.PrintlnByteArray("remotePublicKeyBytes", remotePublicKeyBytes)
	goutils.PrintlnByteArray("remoteSignatureBytes", remoteSignatureBytes)

	remotePublicKey, _ = crypto.PubKeyFromBytes(remotePublicKeyBytes)
	remoteSignature, _ = crypto.SignatureFromBytes(remoteSignatureBytes)

	increase2(receiveNonce)

	return
}

func readLength(conn net.Conn) int {
	length := [2]byte{}
	io.ReadFull(conn, length[:])
	return int(binary.BigEndian.Uint16(length[:]))
}

func sendAuthSignature(conn net.Conn, message []byte, sharedKey *[32]byte, nonce *[24]byte) {
	var out []byte
	out = secretbox.Seal(out[:], message, nonce, sharedKey)
	goutils.PrintlnByteArray("sealed message to send", out)

	sendLength(conn, len(out))
	conn.Write(out)

	increase2(nonce)
	goutils.PrintlnByteArray("sendNonce now is", nonce[:])
}

func sendLength(conn net.Conn, length int) {
	conn.Write(int2bytes(uint16(length)))
}

func int2bytes(number uint16) []byte {
	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, number)
	return bs
}

func increase2(nonce *[24]byte) {
	increase1(nonce)
	increase1(nonce)
}

func increase1(nonce *[24]byte) {
	for i := 23; 0 <= i; i-- {
		nonce[i] += 1
		if nonce[i] != 0 {
			return
		}
	}
}

func buildAuthSignature(publicKey crypto.PubKey, signature crypto.SignatureEd25519) (message []byte) {
	message = append(message, publicKey.Bytes()...)
	message = append(message, signature.Bytes()...)
	return
}

func signChallenge(challenge *[32]byte, localPrivateKey crypto.PrivKeyEd25519) (signature crypto.SignatureEd25519) {
	signature = localPrivateKey.Sign(challenge[:]).(crypto.SignatureEd25519)
	return
}

func genChallenge(lowEphPubKey *[32]byte, highEphPubKey *[32]byte) (challenge *[32]byte) {
	return hash32(append(lowEphPubKey[:], highEphPubKey[:]...))
}
func hash32(input []byte) (res *[32]byte) {
	hasher := sha256.New()
	hasher.Write(input)
	resSlice := hasher.Sum(nil)
	res = new([32]byte)
	copy(res[:], resSlice)
	return
}

func genNonces(lowKey *[32]byte, highKey *[32]byte, localIsLow bool) (receiveNonce, sendNonce *[24]byte) {
	nonce1 := hash24(append(lowKey[:], highKey[:]...))
	nonce2 := new([24]byte)
	copy(nonce2[:], nonce1[:])
	nonce2[len(nonce2)-1] ^= 0x01
	if localIsLow {
		receiveNonce = nonce1
		sendNonce = nonce2
	} else {
		receiveNonce = nonce2
		sendNonce = nonce1
	}
	return
}

func computeSharedSecret(sharedSecret, peerPublicKey, privateKey *[32]byte) {
	box.Precompute(sharedSecret, peerPublicKey, privateKey)
}

func sortKeys(key1, key2 *[32]byte) (low, high *[32]byte) {
	if bytes.Compare(key1[:], key2[:]) < 0 {
		low = key1
		high = key2
	} else {
		low = key2
		high = key1
	}
	return
}

func hash24(input []byte) (res *[24]byte) {
	hasher := ripemd160.New()
	hasher.Write(input)
	resSlice := hasher.Sum(nil)
	res = new([24]byte)
	copy(res[:], resSlice)
	return
}
