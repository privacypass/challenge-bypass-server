package crypto

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// ParseKeyFile decodes a PEM-encoded EC PRIVATE KEY to a big-endian byte slice
// representing the secret scalar, which is the format expected by most curve
// math functions in Go crypto/elliptic.
func ParseKeyFile(keyFilePath string) (elliptic.Curve, []byte, error) {
	encodedKey, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, nil, err
	}
	var skippedTypes []string
	var block *pem.Block

	for {
		block, encodedKey = pem.Decode(encodedKey)

		if block == nil {
			return nil, nil, fmt.Errorf("failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "EC PRIVATE KEY" {
			break
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return privKey.PublicKey.Curve, privKey.D.Bytes(), nil
}
