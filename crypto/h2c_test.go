package crypto

import (
	stdcrypto "crypto"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"testing"
)

// Test that the correct H2C object is returned for all supported curves
func TestGetH2CObjSWU(t *testing.T) {
	checkH2CObject(t, "p256", "sha256", "swu")
}
func TestGetH2CObjInc(t *testing.T) {
	checkH2CObject(t, "p256", "sha256", "increment")
}
func checkH2CObject(t *testing.T, curve, hash, method string) {
	cp := &CurveParams{Curve: curve, Hash: hash, Method: method}
	obj, err := cp.GetH2CObj()
	if err != nil {
		t.Fatal(err)
	}

	if obj.Curve() != elliptic.P256() {
		t.Fatal("Curve is incorrect: ", obj.Curve())
	} else if obj.Hash() != stdcrypto.SHA256 {
		t.Fatal("Hash is incorrect: ", obj.Hash())
	} else if obj.Method() != method {
		t.Fatal("Method is incorrect: ", obj.Method())
	}
}

// Test that the different H2C methods generate valid points on the curve
func TestHashAndIncrementCorrectness(t *testing.T) { HandleTest(t, "increment", hashToCurveCorrectness) }
func TestSWUCorrectness(t *testing.T)              { HandleTest(t, "swu", hashToCurveCorrectness) }
func hashToCurveCorrectness(t *testing.T, h2cObj H2CObject) {
	byteLen := getFieldByteLength(h2cObj.Curve())
	data := make([]byte, byteLen)
	_, err := io.ReadFull(rand.Reader, data)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a point from random bytes
	P, err := h2cObj.HashToCurve(data)
	if err != nil {
		t.Fatal(err)
	}
	if !P.IsOnCurve() {
		t.Error("generated point P wasn't on the curve")
	}

	// Generate a different point from different random bytes
	data[0] ^= 0xFF
	Q, err := h2cObj.HashToCurve(data)
	if err != nil {
		t.Fatal(err)
	}
	if !Q.IsOnCurve() {
		t.Error("generated point Q wasn't on the curve")
	}
	if P.X.Cmp(Q.X) == 0 && P.Y.Cmp(Q.Y) == 0 {
		t.Error("HashToCurve generated duplicate points from different data")
	}
}

// Benchmarks for different H2C methods
func BenchmarkHashAndIncrement(b *testing.B) {
	curveParams := &CurveParams{Curve: "p256", Hash: "sha256", Method: "increment"}
	h2cObj, err := curveParams.GetH2CObj()
	if err != nil {
		b.Fatal(err)
	}
	hashToCurveBench(b, h2cObj)
}
func BenchmarkSWU(b *testing.B) {
	curveParams := &CurveParams{Curve: "p256", Hash: "sha256", Method: "swu"}
	h2cObj, err := curveParams.GetH2CObj()
	if err != nil {
		b.Fatal(err)
	}
	hashToCurveBench(b, h2cObj)
}
func hashToCurveBench(b *testing.B, h2cObj H2CObject) {
	byteLen := getFieldByteLength(h2cObj.Curve())
	data := make([]byte, byteLen)
	_, err := io.ReadFull(rand.Reader, data)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		// Generate a point from random bytes
		_, err := h2cObj.HashToCurve(data)
		if err != nil {
			b.Fatal("hash to curve failed")
		}
	}
}
