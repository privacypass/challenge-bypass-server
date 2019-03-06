// Given a private key, creates a random generator and public commitment to the
// key for a fresh epoch of DLEQ proofs.
//
// +build ignore

package main

import (
	"crypto/elliptic"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/privacypass/challenge-bypass-server/crypto"
)

func main() {
	var keyFile, outFile, curve, hash, method string
	var defaultFilename = fmt.Sprintf("dleq_commitments_%s", time.Now().Format(time.RFC3339))
	flag.StringVar(&keyFile, "key", "", "path to a PEM-encoded EC PRIVATE KEY")
	flag.StringVar(&outFile, "out", defaultFilename, "output path for the commitment")
	flag.StringVar(&method, "h2c_method", "increment", "Method used for hashing to the curve")
	flag.Parse()

	if keyFile == "" {
		flag.Usage()
		return
	}

	curves, keys, err := crypto.ParseKeyFile(keyFile, true)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Get curve and hash from PEM
	curveInPEM := curves[0]
	key := keys[0]
	switch curveInPEM {
	case elliptic.P256():
		curve = "p256"
		hash = "sha256"
	case elliptic.P384():
		curve = "p384"
		hash = "sha384"
	case elliptic.P521():
		curve = "p521"
		hash = "sha512"
	default:
		fmt.Errorf("Unsupported curve choice made: %v", curveInPEM)
	}

	curveParams := &crypto.CurveParams{Curve: curve, Hash: hash, Method: method}
	h2cObj, err := curveParams.GetH2CObj()
	if err != nil {
		fmt.Println(err)
		return
	}

	_, G, err := crypto.NewRandomPoint(h2cObj)
	if err != nil {
		fmt.Println(err)
		return
	}
	Hx, Hy := h2cObj.Curve().ScalarMult(G.X, G.Y, key)
	H, err := crypto.NewPoint(h2cObj.Curve(), Hx, Hy)
	if err != nil {
		fmt.Println(err)
		return
	}

	C := &crypto.Commitment{
		G: G,
		H: H,
	}
	cBytes, err := json.Marshal(C)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = ioutil.WriteFile(outFile, cBytes, os.FileMode(0644))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("commitment files: %v\n", outFile)
	return
}
