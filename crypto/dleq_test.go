package crypto

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256"
	b64 "encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

func setup(curve elliptic.Curve) ([]byte, *Point, *Point, error) {
	// All public keys are going to be generators, so GenerateKey is a handy
	// test function. However, TESTING ONLY. Maintaining the discrete log
	// relationship breaks the token scheme. Ideally the generator points
	// would come from a group PRF or something like Elligator.
	x, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	_, Gx, Gy, err := elliptic.GenerateKey(curve, rand.Reader)
	G := &Point{Curve: curve, X: Gx, Y: Gy}
	if err != nil {
		return nil, nil, nil, err
	}
	_, Mx, My, err := elliptic.GenerateKey(curve, rand.Reader)
	M := &Point{Curve: curve, X: Mx, Y: My}
	if err != nil {
		return nil, nil, nil, err
	}

	return x, G, M, nil
}

func TestValidProof(t *testing.T) {
	curve := elliptic.P256()
	x, G, M, err := setup(curve)
	if err != nil {
		t.Fatal(err)
	}

	Hx, Hy := curve.ScalarMult(G.X, G.Y, x)
	H := &Point{Curve: curve, X: Hx, Y: Hy}
	Zx, Zy := curve.ScalarMult(M.X, M.Y, x)
	Z := &Point{Curve: curve, X: Zx, Y: Zy}

	proof, err := NewProof(crypto.SHA256, G, H, M, Z, new(big.Int).SetBytes(x))
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify() {
		t.Fatal("proof was invalid")
	}

	// Marshal Proof
	prB64, err := proof.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal proof
	prBytes, err := b64.StdEncoding.DecodeString(prB64)
	if err != nil {
		t.Fatal(err)
	}
	ep := &Base64Proof{}
	json.Unmarshal(prBytes, ep)
	proofNew, err := ep.DecodeProof(curve)
	if err != nil {
		t.Fatal(err)
	}
	proofNew.hash = crypto.SHA256
	proofNew.G = G
	proofNew.H = H
	proofNew.M = M
	proofNew.Z = Z

	// Verify new proof
	if !proofNew.Verify() {
		t.Fatal("proof was invalid after marshaling")
	}
}

func TestInvalidProof(t *testing.T) {
	curve := elliptic.P256()
	x, G, M, err := setup(curve)
	if err != nil {
		t.Fatal(err)
	}

	n, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	Hx, Hy := curve.ScalarMult(G.X, G.Y, x)
	H := &Point{Curve: curve, X: Hx, Y: Hy}

	// using Z = nM instead
	Zx, Zy := curve.ScalarMult(M.X, M.Y, n)
	Z := &Point{Curve: curve, X: Zx, Y: Zy}

	proof, err := NewProof(crypto.SHA256, G, H, M, Z, new(big.Int).SetBytes(x))
	if err != nil {
		t.Fatal(err)
	}
	if proof.Verify() {
		t.Fatal("validated an invalid proof")
	}
}
