package crypto

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	"math/big"
	"testing"
)

func TestValidBatchProof(t *testing.T) {
	// All public keys are going to be generators, so GenerateKey is a handy
	// test function. However, TESTING ONLY. Maintaining the discrete log
	// relationship breaks the token scheme.
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
	Hx, Hy := curve.ScalarMult(Gx, Gy, x)
	H := &Point{Curve: curve, X: Hx, Y: Hy}

	M := make([]*Point, 100)
	Z := make([]*Point, 100)
	for i := 0; i < 100; i++ {
		_, Mx, My, err := elliptic.GenerateKey(curve, rand.Reader)
		M[i] = &Point{Curve: curve, X: Mx, Y: My}
		if err != nil {
			t.Fatal(err)
		}
		Zx, Zy := curve.ScalarMult(Mx, My, x)
		Z[i] = &Point{Curve: curve, X: Zx, Y: Zy}
	}

	proof, err := NewBatchProof(crypto.SHA256, G, H, M, Z, new(big.Int).SetBytes(x))
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify() {
		t.Fatal("proof was invalid")
	}
}

func TestInvalidBatchProof(t *testing.T) {
	// All public keys are going to be generators, so GenerateKey is a handy
	// test function. However, TESTING ONLY. Maintaining the discrete log
	// relationship breaks the token scheme.
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
	Hx, Hy := curve.ScalarMult(Gx, Gy, x)
	H := &Point{Curve: curve, X: Hx, Y: Hy}

	M := make([]*Point, 100)
	Z := make([]*Point, 100)
	for i := 0; i < 99; i++ {
		_, Mx, My, err := elliptic.GenerateKey(curve, rand.Reader)
		M[i] = &Point{Curve: curve, X: Mx, Y: My}
		if err != nil {
			t.Fatal(err)
		}
		Zx, Zy := curve.ScalarMult(Mx, My, x)
		Z[i] = &Point{Curve: curve, X: Zx, Y: Zy}
	}

	// and a 100th point with a different discrete log
	m, Mx, My, err := elliptic.GenerateKey(curve, rand.Reader)
	Zx, Zy := curve.ScalarMult(Mx, My, m)
	M[99] = &Point{Curve: curve, X: Mx, Y: My}
	Z[99] = &Point{Curve: curve, X: Zx, Y: Zy}

	proof, err := NewBatchProof(crypto.SHA256, G, H, M, Z, new(big.Int).SetBytes(x))
	if err != nil {
		t.Fatal(err)
	}
	if proof.Verify() {
		t.Fatal("verified an invalid batch proof")
	}
}
