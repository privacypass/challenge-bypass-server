package crypto

import (
	"crypto/elliptic"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// ParseKeyFile decodes a PEM-encoded EC PRIVATE KEY to a big-endian byte slice
// representing the secret scalar, which is the format expected by most curve
// math functions in Go crypto/elliptic.
func ParseKeyFile(keyFilePath string, signingKey bool) ([]elliptic.Curve, [][]byte, error) {
	encodedKey, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, nil, err
	}
	var skippedTypes []string
	var block *pem.Block
	var curves []elliptic.Curve
	var keys [][]byte

	for {
		block, encodedKey = pem.Decode(encodedKey)
		if block == nil {
			return nil, nil, fmt.Errorf("PEM block is nil, this should not happen")
		}

		if block.Type == "EC PRIVATE KEY" {
			privKey, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, err
			}
			curves = append(curves, privKey.PublicKey.Curve)
			keys = append(keys, privKey.D.Bytes())
		} else {
			skippedTypes = append(skippedTypes, block.Type)
		}

		// break if there are no keys left
		if len(encodedKey) == 0 {
			break
		}
	}

	if signingKey && len(keys) > 1 {
		return nil, nil, fmt.Errorf("We should only decode one signing key.")
	}

	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("No key decoded.")
	}

	if len(curves) == 0 {
		return nil, nil, fmt.Errorf("No curve decoded.")
	}

	return curves, keys, nil
}

// Load the commitment to a generator that is currently in use as well.
func ParseCommitmentFile(genFilePath string) ([]byte, []byte, error) {
	commBytes, err := ioutil.ReadFile(genFilePath)
	if err != nil {
		return nil, nil, err
	}

	var commJson map[string]string
	if e := json.Unmarshal(commBytes, &commJson); e != nil {
		return nil, nil, e
	}

	GBytes, err := b64.StdEncoding.DecodeString(commJson["G"])
	if err != nil {
		return nil, nil, err
	}
	HBytes, err := b64.StdEncoding.DecodeString(commJson["H"])
	if err != nil {
		return nil, nil, err
	}

	return GBytes, HBytes, nil
}
