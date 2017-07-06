package crypto

import (
	"crypto"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	_ "crypto/sha256"
	"testing"
)

func TestBlinding(t *testing.T) {
	curve := elliptic.P256()
	_, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
	X := &Point{Curve: curve, X: x, Y: y}
	P, r := BlindPoint(X)
	Xprime := UnblindPoint(P, r)
	if X.X.Cmp(Xprime.X) != 0 || X.Y.Cmp(Xprime.Y) != 0 {
		t.Fatal("unblinding failed to produce the same point")
	}
}

func BenchmarkBlinding(b *testing.B) {
	curve := elliptic.P256()
	_, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
	X := &Point{Curve: curve, X: x, Y: y}
	for i := 0; i < b.N; i++ {
		BlindPoint(X)
	}
}

func BenchmarkUnblinding(b *testing.B) {
	curve := elliptic.P256()
	_, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
	X := &Point{Curve: curve, X: x, Y: y}
	P, r := BlindPoint(X)
	if P == nil || r == nil {
		b.Fatalf("nil ret values")
	}
	for i := 0; i < b.N; i++ {
		UnblindPoint(P, r)
	}
}

// This test runs through the entire "blinded tokens" captcha bypass protocol.
func TestBasicProtocol(t *testing.T) {
	curve := elliptic.P256()
	// Client
	// 1. Generate and store (token, bF, bP)
	token, bP, bF, err := CreateBlindToken()
	if err != nil {
		t.Fatal(err)
	}

	// Server
	// 2a. Have secret key
	x, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 2b. Sign the blind point
	Q := SignPoint(bP, x)

	// Client
	// 3a. Unblind point
	N := UnblindPoint(Q, bF)
	// 3b. Derive MAC key
	sk := DeriveKey(crypto.SHA256, N, token)
	// 3c. MAC the request binding data
	mac := hmac.New(crypto.SHA256.New, sk)
	mac.Write([]byte("example.com"))
	mac.Write([]byte("/index.html"))
	requestBinder := mac.Sum(nil)

	// Server
	// 4a. Derive shared key from token
	T, err := HashToCurve(curve, crypto.SHA256, token)
	if err != nil {
		t.Fatal(err)
	}
	nPrime := SignPoint(T, x)
	skPrime := DeriveKey(crypto.SHA256, nPrime, token)
	// 4b. MAC the request binding data
	verify := hmac.New(crypto.SHA256.New, skPrime)
	verify.Write([]byte("example.com"))
	verify.Write([]byte("/index.html"))
	// 4c. Validate request binding
	valid := hmac.Equal(verify.Sum(nil), requestBinder)
	if !valid {
		t.Fatal("failed redemption")
	}
}
