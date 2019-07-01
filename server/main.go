package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/pat"
	"golang.org/x/crypto/hkdf"
)

var key *ecdsa.PrivateKey

func main() {
	key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	r := pat.New()
	r.Post("/x", x)
	r.Get("/", index)

	port := ":" + os.Getenv("PORT")
	log.Fatal(http.ListenAndServe(port, r))
}

func x(w http.ResponseWriter, r *http.Request) {
	ckey, err := base64.StdEncoding.DecodeString(r.Header.Get("key"))
	if err != nil || len(ckey) == 0 {
		http.Error(w, "Key missing from the header", http.StatusBadRequest)
		return
	}

	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, ckey)

	// derived key buffer
	dkb, _ := curve.ScalarMult(x, y, key.D.Bytes())

	block, err := aes.NewCipher(dkb.Bytes())
	if err != nil {
		http.Error(w, "cipher:"+err.Error(), http.StatusBadRequest)
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, "gcm:"+err.Error(), http.StatusBadRequest)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)
	b64enc, _ := base64.StdEncoding.DecodeString(string(body))

	// THIS IS BEYOND AWESOME SHIT RIGHT HERE!!!!
	// Because of the fucking key derivation, we no longer have to
	// encode or pass in init vectors or nonce to the payload.
	// We can just fucking derive it from the shared secret.
	//
	// Super fly isn't it?
	nonce := hkdf.Extract(sha256.New, dkb.Bytes(), nil)[:12]

	message, err := aesgcm.Open(nil, nonce, b64enc, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	fmt.Fprintln(w, string(message))
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, base64.StdEncoding.EncodeToString(pubKey()))
}

func pubKey() []byte {
	return elliptic.Marshal(key.Curve, key.X, key.Y)
}
