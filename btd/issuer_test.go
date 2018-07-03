package btd

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/elliptic"
	crand "crypto/rand"
	"errors"
	"testing"

	"github.com/brave-intl/challenge-bypass-server/crypto"
)

var (
	testPayload = []byte("Some test payload")
)

// Generates a small but well-formed ISSUE request for testing.
func makeTokenIssueRequest() ([][]byte, [][]byte, []*crypto.Point, [][]byte, error) {
	tokens := make([][]byte, 10)
	bF := make([][]byte, len(tokens))
	bP := make([]*crypto.Point, len(tokens))
	for i := 0; i < len(tokens); i++ {
		token, bPoint, bFactor, err := crypto.CreateBlindToken()
		if err != nil {
			return nil, nil, nil, nil, err
		}
		tokens[i] = token
		bP[i] = bPoint
		bF[i] = bFactor
	}
	marshaledTokenList, err := crypto.BatchMarshalPoints(bP)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return marshaledTokenList, tokens, bP, bF, nil
}

func makeTokenRedempRequest(x []byte, G, H *crypto.Point) ([][]byte, error) {
	// Client
	marshaledTokenList, tokens, bP, bF, err := makeTokenIssueRequest()
	if err != nil {
		return nil, err
	}

	// Client -> (request) -> Server

	// Server
	// Sign the blind points (x is the signing key)
	marshaledPoints, marshaledBP, err := ApproveTokens(marshaledTokenList, x, G, H)
	if err != nil {
		return nil, err
	}

	// Client <- (signed blind tokens) <- Server

	// Client
	// a. Umarshal signed+blinded points
	// XXX: hardcoded curve assumption
	curve := elliptic.P256()
	hash := stdcrypto.SHA256
	xbP, err := crypto.BatchUnmarshalPoints(curve, marshaledPoints)
	if err != nil {
		return nil, err
	}

	// b. Unmarshal and verify batch proof
	// We need to re-sign all the tokens and re-compute
	dleq, err := crypto.UnmarshalBatchProof(curve, marshaledBP)
	if err != nil {
		return nil, err
	}
	dleq.G = G
	dleq.H = H
	Q := signTokens(bP, x)
	dleq.M, dleq.Z, err = recomputeComposites(G, H, bP, Q, hash, curve)
	if err != nil {
		return nil, err
	}
	if !dleq.Verify() {
		return nil, errors.New("Batch proof failed to verify")
	}

	// c. Unblind a point
	xT := crypto.UnblindPoint(xbP[0], bF[0])
	// d. Derive MAC key
	sk := crypto.DeriveKey(hash, xT, tokens[0])
	// e. MAC the request binding data
	reqData := [][]byte{testPayload}
	reqBinder := crypto.CreateRequestBinding(hash, sk, reqData)

	return [][]byte{tokens[0], reqBinder}, nil
}

// Recompute composite values for DLEQ proof
func recomputeComposites(G, Y *crypto.Point, P, Q []*crypto.Point, hash stdcrypto.Hash, curve elliptic.Curve) (*crypto.Point, *crypto.Point, error) {
	compositeM, compositeZ, _, err := crypto.ComputeComposites(hash, curve, G, Y, P, Q)
	return compositeM, compositeZ, err
}

// Sign tokens for verifying DLEQ proof
func signTokens(P []*crypto.Point, key []byte) []*crypto.Point {
	Q := make([]*crypto.Point, len(P))
	for i := 0; i < len(Q); i++ {
		Q[i] = crypto.SignPoint(P[i], key)
	}
	return Q
}

func fakeIssueRequest() ([][]byte, []*crypto.Point, error) {
	reqContents, _, P, _, err := makeTokenIssueRequest()
	if err != nil {
		return nil, nil, err
	}
	return reqContents, P, nil
}

// Fakes the sampling of a signing key
func fakeSigningKey() ([]byte, error) {
	k, _, _, err := elliptic.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// Fakes the procedure of producing commitments for a signing key
func fakeCommitments(key []byte) (*crypto.Point, *crypto.Point, error) {
	curve := elliptic.P256()
	_, Gx, Gy, err := elliptic.GenerateKey(curve, crand.Reader)
	if err != nil {
		return nil, nil, err
	}

	G := &crypto.Point{Curve: curve, X: Gx, Y: Gy}
	Hx, Hy := curve.ScalarMult(Gx, Gy, key)
	H := &crypto.Point{Curve: curve, X: Hx, Y: Hy}

	return G, H, nil
}

// Combines the above two methods
func fakeKeyAndCommitments() ([]byte, *crypto.Point, *crypto.Point, error) {
	x, err := fakeSigningKey()
	if err != nil {
		return nil, nil, nil, err
	}

	G, H, err := fakeCommitments(x)
	if err != nil {
		return nil, nil, nil, err
	}

	return x, G, H, nil
}

func TestTokenIssuance(t *testing.T) {
	reqContents, bP, err := fakeIssueRequest()
	if err != nil {
		t.Fatalf("it's all borked")
	}

	key, G, H, err := fakeKeyAndCommitments()
	if err != nil {
		t.Fatal("couldn't fake the keys and commitments")
	}

	pointData, bpData, err := ApproveTokens(reqContents, key, G, H)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(pointData[0], reqContents[0]) {
		t.Fatal("approved tokens were same as submitted tokens")
	}

	// Verify DLEQ proof
	dleq, err := crypto.UnmarshalBatchProof(elliptic.P256(), bpData)
	if err != nil {
		t.Fatal(err)
	}
	dleq.G = G
	dleq.H = H
	Q := signTokens(bP, key)
	dleq.M, dleq.Z, err = recomputeComposites(G, H, bP, Q, stdcrypto.SHA256, elliptic.P256())
	if !dleq.Verify() {
		t.Fatal("DLEQ proof failed to verify")
	}
}

// Tests token redemption for multiple keys
func TestTokenRedemption(t *testing.T) {
	x1, G1, H1, err := fakeKeyAndCommitments()
	if err != nil {
		t.Fatal(err)
	}
	x2, G2, H2, err := fakeKeyAndCommitments()
	if err != nil {
		t.Fatal(err)
	}
	x3, G3, H3, err := fakeKeyAndCommitments()
	if err != nil {
		t.Fatal(err)
	}

	// Redemption requests for all three keys
	blRedempContents1, err := makeTokenRedempRequest(x1, G1, H1)
	if err != nil {
		t.Fatal(err)
	}
	blRedempContents2, err := makeTokenRedempRequest(x2, G2, H2)
	if err != nil {
		t.Fatal(err)
	}
	blRedempContents3, err := makeTokenRedempRequest(x3, G3, H3)
	if err != nil {
		t.Fatal(err)
	}

	// Only add two keys to check that the third redemption fails
	redeemKeys := [][]byte{x1, x2}

	// Server
	// Check valid token redemption
	err = RedeemToken(blRedempContents1, testPayload, redeemKeys)
	if err != nil {
		t.Fatal(err)
	}
	err = RedeemToken(blRedempContents2, testPayload, redeemKeys)
	if err != nil {
		t.Fatal(err)
	}
	// Check failed redemption
	err = RedeemToken(blRedempContents3, testPayload, redeemKeys)
	if err == nil {
		t.Fatal("This redemption should not be verified correctly.")
	}
}

func TestBadMAC(t *testing.T) {
	x, G, H, err := fakeKeyAndCommitments()
	if err != nil {
		t.Fatal(err)
	}

	blRedempContents, err := makeTokenRedempRequest(x, G, H)
	if err != nil {
		t.Fatal(err)
	}

	// Server
	// Check bad token redemption
	err = RedeemToken(blRedempContents, []byte("bad payload"), [][]byte{x})
	if err == nil {
		t.Fatal("No error occurred even though MAC should be bad")
	}
}
