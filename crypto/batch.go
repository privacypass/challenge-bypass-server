// This implements a non-interactive version of the common-exponent batch
// Schnorr proof from Ryan Henry's thesis. This specifically applies to the
// case where a set of group elements shares a common discrete log with regard
// to a set of generators. Slightly more formally, the case:
//
// (G, q, g_1,...,g_n) and (h_1,...,h_n) ∈ (G)^n with h_i = (g_i)^x for i = 1,...,n
//
// Inspired by an observation of Ian Goldberg's that this "common-exponent" case
// is drastically simpler than a general batch proof. The general idea is that
// we can produce a linear combination of the elements and perform a
// Chaum-Pedersen proof on the resulting composite elements.
//
// See Section 3.2.3.3 for the interactive protocol:
// https://uwspace.uwaterloo.ca/bitstream/handle/10012/8621/Henry_Ryan.pdf
package crypto

import (
	"crypto"
	"errors"
	"math/big"

	"golang.org/x/crypto/sha3"
)

var (
	ErrUnequalPointCounts = errors.New("batch proof had unequal numbers of points")
)

type BatchProof struct {
	P    *Proof
	G, H *Point
	M, Z []*Point
	C    [][]byte
}

func NewBatchProof(hash crypto.Hash, g, h *Point, m []*Point, z []*Point, x *big.Int) (*BatchProof, error) {
	if len(m) != len(z) {
		return nil, ErrUnequalPointCounts
	}

	// The underlying proof and validation steps will do consistency checks.
	curve := g.Curve

	// seed = H(g, h, [m], [z])
	H := hash.New()
	H.Write(g.Marshal())
	H.Write(h.Marshal())
	for i := 0; i < len(m); i++ {
		H.Write(m[i].Marshal())
		H.Write(z[i].Marshal())
	}
	seed := H.Sum(nil)

	prng := sha3.NewShake256()
	prng.Write(seed)

	// Non-interactively generate random c_1, c_2, ... , c_n in Z/qZ
	// to combine m and z elements. Here's how this works:
	// For (m_1, m_2), (z_1, z_2), and (c_1, c_2) we have
	// z_1 = (m_1)^x
	// z_2 = (m_2)^x
	// (z_1^c_1) = (m_1^c_1)^x
	// (z_2^c_2) = (m_2^c_2)^x
	// (z_1^c_1)(z_2^c_2) = [(m_1^c_1)(m_2^c_2)]^x
	// This generalizes to produce composite elements for the entire batch that
	// can be compared to the public key in the standard two-point DLEQ proof.

	Mx, My, Zx, Zy := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	C := make([][]byte, len(m))
	for i := 0; i < len(m); i++ {
		ci, _, err := randScalar(curve, prng)
		if err != nil {
			return nil, err
		}
		// cM = c[i]M[i]
		cMx, cMy := curve.ScalarMult(m[i].X, m[i].Y, ci)
		// cZ = c[i]Z[i]
		cZx, cZy := curve.ScalarMult(z[i].X, z[i].Y, ci)
		// Accumulate
		Mx, My = curve.Add(cMx, cMy, Mx, My)
		Zx, Zy = curve.Add(cZx, cZy, Zx, Zy)
		C[i] = ci
	}
	compositeM := &Point{Curve: curve, X: Mx, Y: My}
	compositeZ := &Point{Curve: curve, X: Zx, Y: Zy}

	proof, err := NewProof(hash, g, h, compositeM, compositeZ, x)
	if err != nil {
		return nil, err
	}
	return &BatchProof{
		P: proof,
		G: g, H: h,
		M: m, Z: z,
		C: C,
	}, nil
}

func (b *BatchProof) IsComplete() bool {
	hasPublicKey := b.G != nil && b.H != nil
	hasPointSets := b.M != nil && b.Z != nil && len(b.M) == len(b.Z)
	return hasPublicKey && hasPointSets && b.C != nil
}

func (b *BatchProof) IsSane() bool {
	if len(b.M) != len(b.Z) {
		return false
	}
	if b.G.Curve != b.H.Curve {
		return false
	}
	for i := 0; i < len(b.M); i++ {
		if b.G.Curve != b.M[i].Curve || b.G.Curve != b.Z[i].Curve {
			return false
		}
		if !b.M[i].IsOnCurve() || !b.Z[i].IsOnCurve() {
			return false
		}
	}
	return true
}

func (b *BatchProof) Verify() bool {
	if !b.IsComplete() || !b.IsSane() {
		return false
	}
	return b.P.Verify()
}
