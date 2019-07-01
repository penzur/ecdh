package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/hkdf"
)

func main() {
	// Generate key pairs with P256 curve
	curve := elliptic.P256()
	key, _ := ecdsa.GenerateKey(curve, rand.Reader)
	pubKey := base64.StdEncoding.EncodeToString(elliptic.Marshal(curve, key.X, key.Y))

	// Get server's public key
	resp, err := http.Get("http://localhost:3000")
	if err != nil {
		return
	}
	body, _ := ioutil.ReadAll(resp.Body)

	// extract server's public key
	cpk, _ := base64.StdEncoding.DecodeString(string(body))
	x, y := elliptic.Unmarshal(curve, cpk)

	// derived secret using server's public key and our local private key
	dkb, _ := curve.ScalarMult(x, y, key.D.Bytes())

	block, err := aes.NewCipher(dkb.Bytes())
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	// HKDF ftw baby!
	nonce := hkdf.Extract(sha256.New, dkb.Bytes(), nil)[:12]

	message := "Hello, World!"

	if len(os.Args) > 1 {
		message = os.Args[1]
	}

	cipherText := aesgcm.Seal(nil, nonce, []byte(message), nil)
	payload := base64.StdEncoding.EncodeToString(cipherText)
	req, _ := http.NewRequest(http.MethodPost, "http://localhost:3001/x", bytes.NewBufferString(payload))

	req.Header.Set("key", pubKey)

	log.Println("  -> sending cipher:", payload)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return
	}

	ct, _ := ioutil.ReadAll(resp.Body)
	log.Println("  <- server responded with: ", string(ct))
}
