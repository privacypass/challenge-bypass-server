// An implementation of an oblivious VRF due to Jarecki et al.
package crypto

import (
	"crypto"
	"crypto/elliptic"
	"crypto/hmac"
	crand "crypto/rand"
	"math/big"
)

// BlindPoint generates a random blinding factor, scalar multiplies it to the
// supplied point, and returns both the new point and the blinding factor.
func BlindPoint(p *Point) (*Point, []byte) {
	r, _, err := randScalar(p.Curve, crand.Reader)
	if err != nil {
		return nil, nil
	}
	Ax, Ay := p.Curve.ScalarMult(p.X, p.Y, r)
	A := &Point{Curve: p.Curve, X: Ax, Y: Ay}
	return A, r
}

// UnblindPoint removes the given blinding factor from the point.
func UnblindPoint(p *Point, blind []byte) *Point {
	r := new(big.Int).SetBytes(blind)
	r.ModInverse(r, p.Curve.Params().N)
	x, y := p.Curve.ScalarMult(p.X, p.Y, r.Bytes())
	return &Point{Curve: p.Curve, X: x, Y: y}
}

// This just executes a scalar mult and returns both the new point and its byte encoding.
// It essentially "signs" a point with the given key.
func SignPoint(P *Point, secret []byte) *Point {
	curve := P.Curve
	Qx, Qy := curve.ScalarMult(P.X, P.Y, secret)
	Q := &Point{Curve: curve, X: Qx, Y: Qy}
	return Q
}

// Derives the shared key used for redemption MACs
func DeriveKey(hash crypto.Hash, N *Point, token []byte) []byte {
	h := hmac.New(hash.New, []byte("hash_derive_key"))
	h.Write(token)
	h.Write(N.Marshal())
	return h.Sum(nil)
}

func CreateRequestBinding(hash crypto.Hash, key []byte, data [][]byte) []byte {
	h := hmac.New(hash.New, key)
	h.Write([]byte("hash_request_binding"))
	for i := 0; i < len(data); i++ {
		h.Write(data[i])
	}
	return h.Sum(nil)
}

func CheckRequestBinding(hash crypto.Hash, key []byte, supplied []byte, observed [][]byte) bool {
	h := hmac.New(hash.New, key)
	h.Write([]byte("hash_request_binding"))
	for i := 0; i < len(observed); i++ {
		h.Write(observed[i])
	}
	return hmac.Equal(supplied, h.Sum(nil))
}

// Creates t, T=H(t), and blinding factor r
func CreateBlindToken() (token []byte, blindPoint *Point, blindFactor []byte, err error) {
	curve := elliptic.P256()
	token, T, err := NewRandomPoint(curve)
	if err != nil {
		return nil, nil, nil, err
	}
	// T = H(token) => Point
	// P := rT
	P, r := BlindPoint(T)
	return token, P, r, nil
}
