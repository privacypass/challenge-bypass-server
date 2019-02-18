package crypto

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	_ "crypto/sha256"
	"testing"
)

func TestBlindingP256(t *testing.T) {
	curve := elliptic.P256()
	_, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
	X := &Point{Curve: curve, X: x, Y: y}
	P, r := BlindPoint(X)
	Xprime := UnblindPoint(P, r)
	if X.X.Cmp(Xprime.X) != 0 || X.Y.Cmp(Xprime.Y) != 0 {
		t.Fatal("unblinding failed to produce the same point")
	}
}

// This test runs through the entire "blinded tokens" captcha bypass protocol
// using the different H2C methods
func TestBasicProtocolIncrement(t *testing.T) { HandleTest(t, "increment", basicProtocol) }
func TestBasicProtocolSWU(t *testing.T)       { HandleTest(t, "swu", basicProtocol) }
func basicProtocol(t *testing.T, h2cObj H2CObject) {
	// Client
	// 1. Generate and store (token, bF, bP)
	token, bP, bF, err := CreateBlindToken(h2cObj)
	if err != nil {
		t.Fatal(err)
	}

	// Server
	// 2a. Have secret key
	x, _, _, err := elliptic.GenerateKey(h2cObj.Curve(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 2b. Sign the blind point
	Q := SignPoint(bP, x)

	// Client
	// 3a. Unblind point
	N := UnblindPoint(Q, bF)
	// 3b. Derive MAC key
	hash := h2cObj.Hash()
	sk := DeriveKey(hash, N, token)
	// 3c. MAC the request binding data
	mac := hmac.New(hash.New, sk)
	mac.Write([]byte("example.com"))
	mac.Write([]byte("/index.html"))
	requestBinder := mac.Sum(nil)

	// Server
	// 4a. Derive shared key from token
	T, err := h2cObj.HashToCurve(token)
	if err != nil {
		t.Fatal(err)
	}
	nPrime := SignPoint(T, x)
	skPrime := DeriveKey(hash, nPrime, token)
	// 4b. MAC the request binding data
	verify := hmac.New(hash.New, skPrime)
	verify.Write([]byte("example.com"))
	verify.Write([]byte("/index.html"))
	// 4c. Validate request binding
	valid := hmac.Equal(verify.Sum(nil), requestBinder)
	if !valid {
		t.Fatal("failed redemption")
	}
}

func BenchmarkBlindingP256(b *testing.B) {
	curve := elliptic.P256()
	_, x, y, _ := elliptic.GenerateKey(curve, rand.Reader)
	X := &Point{Curve: curve, X: x, Y: y}
	for i := 0; i < b.N; i++ {
		BlindPoint(X)
	}
}

func BenchmarkUnblindingP256(b *testing.B) {
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
