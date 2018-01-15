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
	"crypto/elliptic"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/sha3"
	"math/big"
	"strings"
)

var (
	ErrUnequalPointCounts = errors.New("batch proof had unequal numbers of points")

	BATCH_PROOF_RESP_STR = "batch-proof="
)

// We used to send G,H with BP but may as well just use them in P
type BatchProof struct {
	P    *Proof
	M, Z []*Point
	C    [][]byte
}

func NewBatchProof(hash crypto.Hash, g, h *Point, m []*Point, z []*Point, x *big.Int) (*BatchProof, error) {
	if len(m) != len(z) {
		return nil, ErrUnequalPointCounts
	}

	// The underlying proof and validation steps will do consistency checks.
	curve := g.Curve

	compositeM, compositeZ, C, err := ComputeComposites(hash, curve, g, h, m, z)
	if err != nil {
		return nil, err
	}

	proof, err := NewProof(hash, g, h, compositeM, compositeZ, x)
	if err != nil {
		return nil, err
	}
	return &BatchProof{
		P: proof,
		M: m, Z: z,
		C: C,
	}, nil
}

func ComputeComposites(hash crypto.Hash, curve elliptic.Curve, G, Y *Point, P, Q []*Point) (*Point, *Point, [][]byte, error) {
	// seed = H(G, Y, [P], [Qs])
	H := hash.New()
	H.Write(G.Marshal())
	H.Write(Y.Marshal())
	for i := 0; i < len(P); i++ {
		H.Write(P[i].Marshal())
		H.Write(Q[i].Marshal())
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
	C := make([][]byte, len(P))
	for i := 0; i < len(P); i++ {
		ci, _, err := randScalar(curve, prng)
		if err != nil {
			return nil, nil, nil, err
		}
		// cM = c[i]M[i]
		cMx, cMy := curve.ScalarMult(P[i].X, P[i].Y, ci)
		// cZ = c[i]Z[i]
		cZx, cZy := curve.ScalarMult(Q[i].X, Q[i].Y, ci)
		// Accumulate
		Mx, My = curve.Add(cMx, cMy, Mx, My)
		Zx, Zy = curve.Add(cZx, cZy, Zx, Zy)
		C[i] = ci
	}
	compositeM := &Point{Curve: curve, X: Mx, Y: My}
	compositeZ := &Point{Curve: curve, X: Zx, Y: Zy}

	return compositeM, compositeZ, C, nil
}

func (b *BatchProof) IsComplete() bool {
	hasPublicKey := b.P.G != nil && b.P.H != nil
	hasPointSets := b.M != nil && b.Z != nil && len(b.M) == len(b.Z)
	return hasPublicKey && hasPointSets && b.C != nil
}

func (b *BatchProof) IsSane() bool {
	if len(b.M) != len(b.Z) {
		return false
	}
	if b.P.G.Curve != b.P.H.Curve {
		return false
	}
	for i := 0; i < len(b.M); i++ {

		if b.P.G.Curve != b.M[i].Curve || b.P.G.Curve != b.Z[i].Curve {
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

// Marshal a proof to be sent to a client
func (b *BatchProof) MarshalForResp() ([]byte, error) {
	prB64, err := b.P.Marshal()
	if err != nil {
		return nil, err
	}

	bpEnc := map[string]interface{}{"P": prB64}

	bpJson, err := json.Marshal(bpEnc)
	if err != nil {
		return nil, err
	}

	resp := []byte(BATCH_PROOF_RESP_STR + string(bpJson))
	return resp, nil
}

// Takes the batch proof marshaled above and unmarshals it
// Can be used with either the BATCH_PROOF_RESP_STR attached or not
func UnmarshalBatchProof(curve elliptic.Curve, data []byte) (*Proof, error) {
	dataStr := string(data)
	// If the resp string is still attached then remove it
	if strings.Contains(dataStr, BATCH_PROOF_RESP_STR) {
		dataStr = strings.Split(dataStr, BATCH_PROOF_RESP_STR)[1]
	}

	// Unmarshal JSON encoding
	// TODO: do it better than interfaces
	bpJsonBytes := []byte(dataStr)
	var bpDat map[string]interface{}
	json.Unmarshal(bpJsonBytes, &bpDat)

	// Have to decode base64 proof separately
	prBytes, err := b64.StdEncoding.DecodeString(bpDat["P"].(string))
	if err != nil {
		return nil, err
	}
	ep := &Base64Proof{}
	json.Unmarshal(prBytes, ep)
	proof, err := ep.DecodeProof(curve)
	if err != nil {
		return nil, err
	}
	proof.hash = crypto.SHA256

	return proof, nil
}

// Takes a base64 encoded array of points and returns an array of points
func decodeToPointArray(curve elliptic.Curve, b64Arr []interface{}) ([]*Point, error) {
	pArr := make([]*Point, len(b64Arr))
	for i, v := range b64Arr {
		vBytes, err := b64.StdEncoding.DecodeString(v.(string))
		if err != nil {
			return nil, err
		}

		pArr[i] = &Point{}
		err = pArr[i].Unmarshal(curve, vBytes)
		if err != nil {
			return nil, err
		}
	}

	return pArr, nil
}
