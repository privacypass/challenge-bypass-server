package crypto

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestMarshalAndUnmarshalJSONP256(t *testing.T) {
	curve := elliptic.P256()
	_, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	P := &Point{Curve: curve, X: x, Y: y}
	uBytes, err := P.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	Q := &Point{Curve: curve, X: nil, Y: nil}
	err = Q.UnmarshalJSON(uBytes)
	if err != nil {
		t.Fatal(err)
	}
	if P.X.Cmp(Q.X) != 0 || P.Y.Cmp(Q.Y) != 0 {
		t.Fatal("point came back different")
	}
}

func TestUncompressedRoundTripP256(t *testing.T) {
	curve := elliptic.P256()
	_, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	P := &Point{Curve: curve, X: x, Y: y}
	uBytes := P.Marshal()
	Q := &Point{Curve: curve, X: nil, Y: nil}
	err = Q.Unmarshal(curve, uBytes)
	if err != nil {
		t.Fatal(err)
	}
	if P.X.Cmp(Q.X) != 0 || P.Y.Cmp(Q.Y) != 0 {
		t.Fatal("point came back different")
	}
}

func TestCompressedRoundTripP256(t *testing.T) {
	curve := elliptic.P256()
	byteLen := (curve.Params().BitSize + 7) >> 3
	bigTwo := new(big.Int).SetInt64(int64(2))
	_, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	yBit := new(big.Int).Mod(y, bigTwo).Int64()

	P := &Point{Curve: curve, X: x, Y: y}
	uBytes := P.Marshal()
	cBytes := make([]byte, byteLen+1)
	copy(cBytes[1:], uBytes[1:])
	if yBit == 0 {
		cBytes[0] = 0x02
	}
	if yBit == 1 {
		cBytes[0] = 0x03
	}

	Q := &Point{Curve: curve, X: nil, Y: nil}
	err = Q.Unmarshal(curve, cBytes)
	if err != nil {
		t.Fatal(err)
	}

	if P.X.Cmp(Q.X) != 0 || P.Y.Cmp(Q.Y) != 0 {
		t.Fatal("point came back different")
	}
}

var pointCompressionTests = []struct {
	curve      elliptic.Curve
	name       string
	compressed string
	x, y       string
}{
	// Generator from SEC2 2.7.2, Recommended Parameters secp256r1.
	{
		name:       "P-256 standard generator",
		curve:      elliptic.P256(),
		compressed: "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
		x:          "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
		y:          "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
	},
}

func TestPointCompressionP256(t *testing.T) {
	for _, tt := range pointCompressionTests {
		P := &Point{}
		Px, ok := new(big.Int).SetString(tt.x, 16)
		if !ok {
			t.Errorf("couldn't parse x string for %s", tt.name)
		}
		Py, ok := new(big.Int).SetString(tt.y, 16)
		if !ok {
			t.Errorf("couldn't parse y string for %s", tt.name)
		}
		cBytes, _ := hex.DecodeString(tt.compressed)
		err := P.Unmarshal(tt.curve, cBytes)
		if err != nil {
			t.Errorf("couldn't unmarshal compressed point for %s", tt.name)
		}
		if P.X.Cmp(Px) != 0 || P.Y.Cmp(Py) != 0 {
			t.Errorf("got the wrong result for %s", tt.name)
		}
	}
}

// Test batched proof marshaling for all H2C methods in an entire round-trip of
// the protocol
func TestBatchMarshalRoundTripInc(t *testing.T) { HandleTest(t, "increment", batchMarshalRoundTrip) }
func TestBatchMarshalRoundTripSWU(t *testing.T) { HandleTest(t, "swu", batchMarshalRoundTrip) }
func batchMarshalRoundTrip(t *testing.T, h2cObj H2CObject) {
	points := make([]*Point, 50)
	for i := 0; i < len(points); i++ {
		_, point, err := NewRandomPoint(h2cObj)
		if err != nil {
			t.Fatal(err)
		}
		points[i] = point
	}
	marshaledPointList, err := BatchMarshalPoints(points)
	if err != nil {
		t.Fatal(err)
	}
	samePoints, err := BatchUnmarshalPoints(elliptic.P256(), marshaledPointList)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != len(samePoints) {
		t.Fatal("point slices were different lengths")
	}
	for i := 0; i < len(points); i++ {
		if points[i].X.Cmp(samePoints[i].X) != 0 || points[i].Y.Cmp(samePoints[i].Y) != 0 {
			t.Fatal("points came back different")
		}
	}
}

func BenchmarkDecompression(b *testing.B) {
	cPoint := "02ee8b4533f32ddbb5775cc793fa3a842fcc7033b57c9820f91c54142651d316c8"
	cBytes, err := hex.DecodeString(cPoint)
	if err != nil {
		b.Fatal(err)
	}
	Q := &Point{Curve: elliptic.P256(), X: nil, Y: nil}
	for i := 0; i < b.N; i++ {
		err := Q.Unmarshal(Q.Curve, cBytes)
		if err != nil {
			b.Error(err)
		}
	}
}
