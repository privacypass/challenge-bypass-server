// An implementation of the widely-used (honest-verifier) NIZK proof of
// discrete logarithm equality originally described in the Chaum and Pedersen
// paper "Wallet Databases with Observers", using Go's standard crypto/elliptic
// package.
//
// This implementation potentially minimizes the amount of data that needs to
// be sent to the verifier by including the intermediate proof values (called
// a, b in the paper) in the Fiat-Shamir hash step and using hash comparison to
// determine proof validity instead of group element equality.
package crypto

import (
	"crypto"
	"crypto/elliptic"
	"crypto/hmac"
	crand "crypto/rand"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

var (
	ErrInconsistentCurves = errors.New("points are on different curves")
)

// A JSON structure for marshaling the public commitment values
type Commitment struct {
	G *Point `json:"G"`
	H *Point `json:"H"`
}

type Proof struct {
	G, M *Point   // generators known by both parties
	H, Z *Point   // "public keys" we want to compare
	R    *big.Int // response value
	C    *big.Int // hash of intermediate proof values to streamline equality checks

	hash crypto.Hash
}

type Base64Proof struct {
	G, M string
	H, Z string
	R    string
	C    string
}

func (p *Proof) IsComplete() bool {
	return p.G != nil && p.M != nil && p.H != nil && p.Z != nil && p.R != nil && p.C != nil
}

func (p *Proof) IsSane() bool {
	if p.G.Curve != p.H.Curve || p.H.Curve != p.M.Curve || p.M.Curve != p.Z.Curve {
		return false
	}
	if !p.G.IsOnCurve() || !p.H.IsOnCurve() || !p.M.IsOnCurve() || !p.Z.IsOnCurve() {
		return false
	}
	return true
}

// Given g, h, m, z such that g, m are generators and h = g^x, z = m^x,
// compute a proof that log_g(h) == log_m(z). If (g, h, m, z) are already known
// to the verifier, then (c, r) is sufficient to check the proof.
func NewProof(hash crypto.Hash, g, h, m, z *Point, x *big.Int) (*Proof, error) {
	if g.Curve != h.Curve || h.Curve != m.Curve || m.Curve != z.Curve {
		return nil, ErrInconsistentCurves
	}
	if !g.IsOnCurve() || !h.IsOnCurve() || !m.IsOnCurve() || !z.IsOnCurve() {
		return nil, ErrPointOffCurve
	}
	curve := g.Curve

	// s is a random element of Z/qZ
	sBytes, s, err := randScalar(curve, crand.Reader)
	if err != nil {
		return nil, err
	}

	// (a, b) = (g^s, m^s)
	Ax, Ay := curve.ScalarMult(g.X, g.Y, sBytes)
	Bx, By := curve.ScalarMult(m.X, m.Y, sBytes)

	// c = H(g, h, z, a, b)
	// Note: in the paper this is H(m, z, a, b) to constitute a signature over
	// m and prevent existential forgery. What we care about here isn't
	// committing to a particular m but the equality with the specific public
	// key h.
	H := hash.New()
	H.Write(g.Marshal())
	H.Write(h.Marshal())
	H.Write(m.Marshal())
	H.Write(z.Marshal())
	H.Write(elliptic.Marshal(curve, Ax, Ay))
	H.Write(elliptic.Marshal(curve, Bx, By))
	cBytes := H.Sum(nil)

	// Expressing this as r = s - cx instead of r = s + cx saves us an
	// inversion of c when calculating A and B on the verification side.
	c := new(big.Int).SetBytes(cBytes)
	c.Mod(c, curve.Params().N) // c = c (mod q)
	r := new(big.Int).Neg(c)   // r = -c
	r.Mul(r, x)                // r = -cx
	r.Add(r, s)                // r = s - cx
	r.Mod(r, curve.Params().N) // r = r (mod q)

	proof := &Proof{
		G: g, M: m,
		H: h, Z: z,
		R: r, C: c,
		hash: hash,
	}
	return proof, nil
}

func (pr *Proof) Verify() bool {
	if !pr.IsComplete() || !pr.IsSane() {
		return false
	}
	curve := pr.G.Curve

	// Prover gave us c = H(h, z, a, b)
	// Calculate rG and rM, then C' = H(h, z, rG + cH, rM + cZ).
	// C == C' is equivalent to checking the equalities.

	// a = (g^r)(h^c)
	// A = rG + cH
	cHx, cHy := curve.ScalarMult(pr.H.X, pr.H.Y, pr.C.Bytes())
	rGx, rGy := curve.ScalarMult(pr.G.X, pr.G.Y, pr.R.Bytes())
	Ax, Ay := curve.Add(rGx, rGy, cHx, cHy)

	// b = (m^r)(z^c)
	// B = rM + cZ
	cZx, cZy := curve.ScalarMult(pr.Z.X, pr.Z.Y, pr.C.Bytes())
	rMx, rMy := curve.ScalarMult(pr.M.X, pr.M.Y, pr.R.Bytes())
	Bx, By := curve.Add(rMx, rMy, cZx, cZy)

	// C' = H(g, h, z, a, b) == C
	H := pr.hash.New()
	H.Write(pr.G.Marshal())
	H.Write(pr.H.Marshal())
	H.Write(pr.M.Marshal())
	H.Write(pr.Z.Marshal())
	H.Write(elliptic.Marshal(curve, Ax, Ay))
	H.Write(elliptic.Marshal(curve, Bx, By))
	c := H.Sum(nil)
	return hmac.Equal(pr.C.Bytes(), c)
}

// Base64 encode the fields of the DLEQ proof for sending back to client
func (pr *Proof) EncodeProof() *Base64Proof {
	ep := &Base64Proof{}
	ep.G = b64.StdEncoding.EncodeToString(pr.G.Marshal())
	ep.H = b64.StdEncoding.EncodeToString(pr.H.Marshal())
	ep.M = b64.StdEncoding.EncodeToString(pr.M.Marshal())
	ep.Z = b64.StdEncoding.EncodeToString(pr.Z.Marshal())
	ep.R = b64.StdEncoding.EncodeToString(pr.R.Bytes())
	ep.C = b64.StdEncoding.EncodeToString(pr.C.Bytes())

	return ep
}

// Decode base64 proofs
func (ep *Base64Proof) DecodeProof(curve elliptic.Curve) (*Proof, error) {
	pr := &Proof{}
	var err error

	// Decoded each of the points from b64 to *Point format
	pr.G, err = decodePoint(curve, ep.G)
	if err != nil {
		return nil, err
	}

	pr.M, err = decodePoint(curve, ep.M)
	if err != nil {
		return nil, err
	}

	pr.H, err = decodePoint(curve, ep.H)
	if err != nil {
		return nil, err
	}

	pr.Z, err = decodePoint(curve, ep.Z)
	if err != nil {
		return nil, err
	}

	// decode big.Int fields
	RBytes, err := b64.StdEncoding.DecodeString(ep.R)
	if err != nil {
		return nil, err
	}
	pr.R = new(big.Int).SetBytes(RBytes)

	CBytes, err := b64.StdEncoding.DecodeString(ep.C)
	if err != nil {
		return nil, err
	}
	pr.C = new(big.Int).SetBytes(CBytes)

	return pr, nil
}

// Decodes a point from b64 representation
func decodePoint(curve elliptic.Curve, b64Point string) (*Point, error) {
	p := &Point{}
	pBytes, err := b64.StdEncoding.DecodeString(b64Point)
	if err != nil {
		return nil, err
	}
	err = p.Unmarshal(curve, pBytes)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// Marshal proof as part of BatchProof objects for responses
func (pr *Proof) Marshal() (string, error) {
	ep := pr.EncodeProof()
	epJsonBytes, err := json.Marshal(ep)
	if err != nil {
		return "", err
	}
	prB64 := b64.StdEncoding.EncodeToString(epJsonBytes)
	return prB64, nil
}
