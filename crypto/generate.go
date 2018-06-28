package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
)

func GeneratePrivateKey() (string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)

	if err != nil {
		return "", err
	}

	privBlock := pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyBytes,
	}

	privatePEM := pem.EncodeToMemory(&privBlock)

	return string(privatePEM), nil
}
