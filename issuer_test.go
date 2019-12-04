package btd

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/elliptic"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/privacypass/challenge-bypass-server/crypto"
)

var (
	testHost = []byte("example.com")
	testPath = []byte("/index.html")
)

// Generates a small but well-formed ISSUE request for testing.
func makeTokenIssueRequest(h2cObj crypto.H2CObject) (*BlindTokenRequest, [][]byte, []*crypto.Point, [][]byte, error) {
	tokens := make([][]byte, 10)
	bF := make([][]byte, len(tokens))
	bP := make([]*crypto.Point, len(tokens))
	for i := 0; i < len(tokens); i++ {
		token, bPoint, bFactor, err := crypto.CreateBlindToken(h2cObj)
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

	request := &BlindTokenRequest{
		Type:     "Issue",
		Contents: marshaledTokenList, // this is [][]byte, not JSON
	}
	return request, tokens, bP, bF, nil
}

func makeTokenRedempRequest(x []byte, G, H *crypto.Point, h2cObj crypto.H2CObject) (*BlindTokenRequest, error) {
	// Client
	request, tokens, bP, bF, err := makeTokenIssueRequest(h2cObj)
	if err != nil {
		return nil, err
	}

	// Client -> (request) -> Server

	// Server
	// Sign the blind points (x is the signing key)
	marshaledData, err := ApproveTokens(*request, x, "1.1", G, H)
	if err != nil {
		return nil, err
	}

	// Client <- (signed blind tokens) <- Server

	// Client
	// a. Umarshal signed+blinded points
	// XXX: hardcoded curve assumption
	marshaledPoints, marshaledBP := marshaledData.Sigs, marshaledData.Proof
	xbP, err := crypto.BatchUnmarshalPoints(h2cObj.Curve(), marshaledPoints)
	if err != nil {
		return nil, err
	}

	// b. Unmarshal and verify batch proof
	// We need to re-sign all the tokens and re-compute
	dleq, err := crypto.UnmarshalBatchProof(h2cObj.Curve(), marshaledBP)
	if err != nil {
		return nil, err
	}
	dleq.G = G
	dleq.H = H
	Q := signTokens(bP, x)
	dleq.M, dleq.Z, err = recomputeComposites(G, H, bP, Q, h2cObj.Hash(), h2cObj.Curve())
	if err != nil {
		return nil, err
	}
	if !dleq.Verify() {
		return nil, errors.New("Batch proof failed to verify")
	}

	// c. Unblind a point
	xT := crypto.UnblindPoint(xbP[0], bF[0])
	// d. Derive MAC key
	sk := crypto.DeriveKey(h2cObj.Hash(), xT, tokens[0])
	// e. MAC the request binding data
	reqData := [][]byte{testHost, testPath}
	reqBinder := crypto.CreateRequestBinding(h2cObj.Hash(), sk, reqData)
	contents := [][]byte{tokens[0], reqBinder}
	var h2cParamsBytes []byte
	if h2cObj.Method() == "swu" {
		curveParams := &crypto.CurveParams{Curve: "p256", Hash: "sha256", Method: "swu"}
		h2cParamsBytes, err = json.Marshal(curveParams)
		if err != nil {
			return nil, err
		}
		contents = append(contents, h2cParamsBytes)
	}

	redeemRequest := &BlindTokenRequest{
		Type:     "Redeem",
		Contents: contents,
	}

	return redeemRequest, nil
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

// This function exists only for testing. The wrapper is a transport format
// induced by internal systems. It should be irrelevant to third-party
// implementations.
func wrapTokenRequest(req *BlindTokenRequest) *BlindTokenRequestWrapper {
	encoded, _ := MarshalRequest(req)
	wrappedRequest := &BlindTokenRequestWrapper{
		Request: encoded,
	}
	return wrappedRequest
}

func fakeWrappedRequest(h2cObj crypto.H2CObject) ([]byte, error) {
	req, _, _, _, err := makeTokenIssueRequest(h2cObj)
	if err != nil {
		return nil, err
	}
	wrapped := wrapTokenRequest(req)
	return MarshalRequest(wrapped)
}

func fakeIssueRequest(h2cObj crypto.H2CObject) ([]byte, []*crypto.Point, error) {
	req, _, P, _, err := makeTokenIssueRequest(h2cObj)
	if err != nil {
		return nil, nil, err
	}
	m, err := MarshalRequest(req)
	if err != nil {
		return nil, nil, err
	}
	return m, P, nil
}

// Fakes the sampling of a signing key
func fakeSigningKey(h2cObj crypto.H2CObject) ([]byte, error) {
	k, _, _, err := elliptic.GenerateKey(h2cObj.Curve(), crand.Reader)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// Fakes the procedure of producing commitments for a signing key
func fakeCommitments(key []byte, h2cObj crypto.H2CObject) (*crypto.Point, *crypto.Point, error) {
	_, Gx, Gy, err := elliptic.GenerateKey(h2cObj.Curve(), crand.Reader)
	if err != nil {
		return nil, nil, err
	}

	curve := h2cObj.Curve()
	G := &crypto.Point{Curve: curve, X: Gx, Y: Gy}
	Hx, Hy := curve.ScalarMult(Gx, Gy, key)
	H := &crypto.Point{Curve: curve, X: Hx, Y: Hy}

	return G, H, nil
}

// Combines the above two methods
func fakeKeyAndCommitments(h2cObj crypto.H2CObject) ([]byte, *crypto.Point, *crypto.Point, error) {
	x, err := fakeSigningKey(h2cObj)
	if err != nil {
		return nil, nil, nil, err
	}

	G, H, err := fakeCommitments(x, h2cObj)
	if err != nil {
		return nil, nil, nil, err
	}

	return x, G, H, nil
}

// Tests that wrapped requests can be parsed for all curve choices
func TestParseWrappedRequestIncrement(t *testing.T) {
	crypto.HandleTest(t, "increment", parseWrappedRequest)
}
func TestParseWrappedRequestSWU(t *testing.T) { crypto.HandleTest(t, "swu", parseWrappedRequest) }
func parseWrappedRequest(t *testing.T, h2cObj crypto.H2CObject) {
	reqBytes, err := fakeWrappedRequest(h2cObj)
	if err != nil {
		t.Fatalf("it's all borked: %v", err)
	}

	var wrapped BlindTokenRequestWrapper
	var request BlindTokenRequest

	err = json.Unmarshal(reqBytes, &wrapped)
	if err != nil {
		t.Fatal(err)
	}

	err = json.Unmarshal(wrapped.Request, &request)
	if err != nil {
		t.Fatal(err)
	}

	if request.Type != ISSUE {
		t.Errorf("got req type %s when expected %s", request.Type, ISSUE)
	}
}

// Tests that token issuance works correctly for all curve choices
func TestTokenIssuanceIncrement(t *testing.T) { crypto.HandleTest(t, "increment", tokenIssuance) }
func TestTokenIssuanceSWU(t *testing.T)       { crypto.HandleTest(t, "swu", tokenIssuance) }
func tokenIssuance(t *testing.T, h2cObj crypto.H2CObject) {
	reqBytes, bP, err := fakeIssueRequest(h2cObj)
	if err != nil {
		t.Fatalf("it's all borked: %v", err)
	}

	var req BlindTokenRequest
	err = json.Unmarshal(reqBytes, &req)
	if err != nil {
		t.Fatal(err)
	}
	if req.Type != ISSUE {
		t.Fatalf("got issue request with type %s", req.Type)
	}

	key, G, H, err := fakeKeyAndCommitments(h2cObj)
	if err != nil {
		t.Fatal("couldn't fake the keys and commitments")
	}

	marshaledResp, err := ApproveTokens(req, key, "1.1", G, H)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(marshaledResp.Sigs[0], req.Contents[0]) {
		t.Fatal("approved tokens were same as submitted tokens")
	}

	// Verify DLEQ proof
	dleq, err := crypto.UnmarshalBatchProof(h2cObj.Curve(), marshaledResp.Proof)
	if err != nil {
		t.Fatal(err)
	}
	dleq.G = G
	dleq.H = H
	Q := signTokens(bP, key)
	dleq.M, dleq.Z, _ = recomputeComposites(G, H, bP, Q, h2cObj.Hash(), h2cObj.Curve())
	if !dleq.Verify() {
		t.Fatal("DLEQ proof failed to verify")
	}
}

// Tests token redemption for multiple keys and curve implementations
func TestTokenRedemptionIncrement(t *testing.T) { crypto.HandleTest(t, "increment", tokenRedemption) }
func TestTokenRedemptionSWU(t *testing.T)       { crypto.HandleTest(t, "swu", tokenRedemption) }
func tokenRedemption(t *testing.T, h2cObj crypto.H2CObject) {
	x1, G1, H1, err := fakeKeyAndCommitments(h2cObj)
	if err != nil {
		t.Fatal(err)
	}
	x2, G2, H2, err := fakeKeyAndCommitments(h2cObj)
	if err != nil {
		t.Fatal(err)
	}
	x3, G3, H3, err := fakeKeyAndCommitments(h2cObj)
	if err != nil {
		t.Fatal(err)
	}

	// Redemption requests for all three keys
	blRedempreq1, err := makeTokenRedempRequest(x1, G1, H1, h2cObj)
	if err != nil {
		t.Fatal(err)
	}
	blRedempreq2, err := makeTokenRedempRequest(x2, G2, H2, h2cObj)
	if err != nil {
		t.Fatal(err)
	}
	blRedempreq3, err := makeTokenRedempRequest(x3, G3, H3, h2cObj)
	if err != nil {
		t.Fatal(err)
	}

	// Only add two keys to check that the third redemption fails
	redeemKeys := [][]byte{x1, x2}

	// Server
	// Check valid token redemption
	err = RedeemToken(*blRedempreq1, testHost, testPath, redeemKeys)
	if err != nil {
		t.Fatal(err)
	}
	err = RedeemToken(*blRedempreq2, testHost, testPath, redeemKeys)
	if err != nil {
		t.Fatal(err)
	}
	// Check failed redemption
	err = RedeemToken(*blRedempreq3, testHost, testPath, redeemKeys)
	if err == nil {
		t.Fatal("This redemption should not be verified correctly.")
	}
}

// Tests that MAC fails for bad values for each curve setting
func TestBadMACIncrement(t *testing.T) { crypto.HandleTest(t, "increment", badMAC) }
func TestBadMACSWU(t *testing.T)       { crypto.HandleTest(t, "swu", badMAC) }
func badMAC(t *testing.T, h2cObj crypto.H2CObject) {
	x, G, H, err := fakeKeyAndCommitments(h2cObj)
	if err != nil {
		t.Fatal(err)
	}

	blRedempreq, err := makeTokenRedempRequest(x, G, H, h2cObj)
	if err != nil {
		t.Fatal(err)
	}

	// Server
	// Check bad token redemption
	err = RedeemToken(*blRedempreq, []byte("something bad"), []byte("something worse"), [][]byte{x})
	if err == nil {
		t.Fatal("No error occurred even though MAC should be bad")
	}
}
