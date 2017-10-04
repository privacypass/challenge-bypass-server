package btd

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/elliptic"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cloudflare/btd/crypto"
)

var (
	testHost = []byte("example.com")
	testPath = []byte("/index.html")
)

// Generates a small but well-formed ISSUE request for testing.
func makeTokenIssueRequest() (*BlindTokenRequest, [][]byte, []*crypto.Point, [][]byte, error) {
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

	request := &BlindTokenRequest{
		Type:     "Issue",
		Contents: marshaledTokenList, // this is [][]byte, not JSON
	}
	return request, tokens, bP, bF, nil
}

func makeTokenRedempRequest() (*BlindTokenRequest, []byte, error) {
	// Client
	request, tokens, _, bF, err := makeTokenIssueRequest()
	if err != nil {
		return nil, nil, err
	}

	// Client -> (request) -> Server

	// Server
	// 2a. Have secret key
	x, _, _, err := elliptic.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// 2b. generate commitment
	G, H, err := fakeCommitments(x)
	if err != nil {
		return nil, nil, errors.New("couldn't even fake the commitments")
	}

	// 2c. Sign the blind points
	marshaledData, err := ApproveTokens(*request, x, G, H)
	if err != nil {
		return nil, nil, err
	}

	// Client <- (signed blind tokens) <- Server

	// Client
	// 3a. Umarshal signed+blinded points
	// XXX: hardcoded curve assumption
	curve := elliptic.P256()
	hash := stdcrypto.SHA256
	marshaledPoints, marshaledBP := crypto.GetMarshaledPointsAndDleq(marshaledData)
	xbP, err := crypto.BatchUnmarshalPoints(curve, marshaledPoints)
	if err != nil {
		return nil, nil, err
	}

	// 3b. Unmarshal and verify batch proof
	batchProof := &crypto.BatchProof{}
	err = batchProof.Unmarshal(curve, marshaledBP)
	if err != nil {
		return nil, nil, err
	}
	if !batchProof.Verify() {
		return nil, nil, errors.New("Batch proof failed to verify")
	}

	// 3c. Unblind a point
	xT := crypto.UnblindPoint(xbP[0], bF[0])
	// 3d. Derive MAC key
	sk := crypto.DeriveKey(hash, xT, tokens[0])
	// 3e. MAC the request binding data
	reqData := [][]byte{testHost, testPath}
	reqBinder := crypto.CreateRequestBinding(hash, sk, reqData)

	redeemRequest := &BlindTokenRequest{
		Type:     "Redeem",
		Contents: [][]byte{tokens[0], reqBinder},
	}

	return redeemRequest, x, nil
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

func fakeWrappedRequest() ([]byte, error) {
	req, _, _, _, err := makeTokenIssueRequest()
	if err != nil {
		return nil, err
	}
	wrapped := wrapTokenRequest(req)
	return MarshalRequest(wrapped)
}

func fakeIssueRequest() ([]byte, error) {
	req, _, _, _, err := makeTokenIssueRequest()
	if err != nil {
		return nil, err
	}
	return MarshalRequest(req)
}

func fakeSigningKey() ([]byte, error) {
	k, _, _, err := elliptic.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, err
	}
	return k, nil
}

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

func TestParseWrappedRequest(t *testing.T) {
	reqBytes, err := fakeWrappedRequest()
	if err != nil {
		t.Fatalf("it's all borked")
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

func TestTokenIssuance(t *testing.T) {
	reqBytes, err := fakeIssueRequest()
	if err != nil {
		t.Fatalf("it's all borked")
	}

	var req BlindTokenRequest
	err = json.Unmarshal(reqBytes, &req)
	if err != nil {
		t.Fatal(err)
	}
	if req.Type != ISSUE {
		t.Fatalf("got issue request with type %s", req.Type)
	}

	key, err := fakeSigningKey()
	if err != nil {
		t.Fatal("couldn't even fake a key")
	}

	G, H, err := fakeCommitments(key)
	if err != nil {
		t.Fatal("couldn't even fake the commitments")
	}

	marshaledResp, err := ApproveTokens(req, key, G, H)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(marshaledResp[0], req.Contents[0]) {
		t.Fatal("approved tokens were same as submitted tokens")
	}

	// Verify DLEQ proof
	dleqIndex := len(marshaledResp) - 1
	batchDleq := &crypto.BatchProof{}
	batchDleq.Unmarshal(elliptic.P256(), marshaledResp[dleqIndex])
	if !batchDleq.Verify() {
		t.Fatal("Batch DLEQ proof failed to verify")
	}
}

func TestTokenRedemption(t *testing.T) {
	// Client -> (tokens[0], requestBinder) -> Server
	blRedempreq, x, err := makeTokenRedempRequest()
	if err != nil {
		t.Fatal(err)
	}

	// Server
	// Check valid token redemption
	err = RedeemToken(*blRedempreq, testHost, testPath, x)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBadMAC(t *testing.T) {
	blRedempreq, x, err := makeTokenRedempRequest()
	if err != nil {
		t.Fatal(err)
	}

	// Server
	// Check bad token redemption
	err = RedeemToken(*blRedempreq, []byte("something bad"), []byte("something worse"), x)
	if err == nil {
		t.Fatal("No error occurred even though MAC should be bad")
	}
}
