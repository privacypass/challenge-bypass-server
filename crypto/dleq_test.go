package crypto

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	"math/big"
	"testing"
)

func TestValidProof(t *testing.T) {
	// All public keys are going to be generators, so GenerateKey is a handy
	// test function. However, TESTING ONLY. Maintaining the discrete log
	// relationship breaks the token scheme. Ideally the generator points
	// would come from a group PRF or something like Elligator.
	curve := elliptic.P256()
	x, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, Gx, Gy, err := elliptic.GenerateKey(curve, rand.Reader)
	G := &Point{Curve: curve, X: Gx, Y: Gy}
	if err != nil {
		t.Fatal(err)
	}
	_, Mx, My, err := elliptic.GenerateKey(curve, rand.Reader)
	M := &Point{Curve: curve, X: Mx, Y: My}
	if err != nil {
		t.Fatal(err)
	}

	Hx, Hy := curve.ScalarMult(Gx, Gy, x)
	H := &Point{Curve: curve, X: Hx, Y: Hy}
	Zx, Zy := curve.ScalarMult(Mx, My, x)
	Z := &Point{Curve: curve, X: Zx, Y: Zy}

	proof, err := NewProof(crypto.SHA256, G, H, M, Z, new(big.Int).SetBytes(x))
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify() {
		t.Fatal("proof was invalid")
	}
}

func TestInvalidProof(t *testing.T) {
	// All public keys are going to be generators, so GenerateKey is a handy
	// test function. However, TESTING ONLY. Maintaining the discrete log
	// relationship breaks the token scheme. Ideally the generator points
	// would come from a group PRF or something like Elligator.
	curve := elliptic.P256()
	x, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, Gx, Gy, err := elliptic.GenerateKey(curve, rand.Reader)
	G := &Point{Curve: curve, X: Gx, Y: Gy}
	if err != nil {
		t.Fatal(err)
	}
	_, Mx, My, err := elliptic.GenerateKey(curve, rand.Reader)
	M := &Point{Curve: curve, X: Mx, Y: My}
	if err != nil {
		t.Fatal(err)
	}

	n, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	Hx, Hy := curve.ScalarMult(Gx, Gy, x)
	H := &Point{Curve: curve, X: Hx, Y: Hy}

	// using Z = nM instead
	Zx, Zy := curve.ScalarMult(Mx, My, n)
	Z := &Point{Curve: curve, X: Zx, Y: Zy}

	proof, err := NewProof(crypto.SHA256, G, H, M, Z, new(big.Int).SetBytes(x))
	if err != nil {
		t.Fatal(err)
	}
	if proof.Verify() {
		t.Fatal("validated an invalid proof")
	}
}
