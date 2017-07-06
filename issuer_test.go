package btd

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/elliptic"
	crand "crypto/rand"
	"encoding/json"
	"testing"

	"github.com/cloudflare/btd/crypto"
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

	marshaledTokenList, err := ApproveTokens(req, key)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(marshaledTokenList[0], req.Contents[0]) {
		t.Fatal("approved tokens were same as submitted tokens")
	}
}

// TODO: TestDLEQProof

func TestTokenRedemption(t *testing.T) {
	// Client
	request, tokens, _, bF, err := makeTokenIssueRequest()
	if err != nil {
		t.Fatal(err)
	}

	// Client -> (request) -> Server

	// Server
	// 2a. Have secret key
	x, _, _, err := elliptic.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 2b. Sign the blind points
	marshaledTokenList, err := ApproveTokens(*request, x)
	if err != nil {
		t.Fatal(err)
	}

	// Client <- (signed blind tokens) <- Server

	// Client
	// 3a. Umarshal signed+blinded points
	// XXX: hardcoded curve assumption
	curve := elliptic.P256()
	hash := stdcrypto.SHA256
	xbP, err := crypto.BatchUnmarshalPoints(curve, marshaledTokenList)
	if err != nil {
		t.Fatal(err)
	}
	// 3b. Unblind a point
	xT := crypto.UnblindPoint(xbP[0], bF[0])
	// 3c. Derive MAC key
	sk := crypto.DeriveKey(hash, xT, tokens[0])
	// 3d. MAC the request binding data
	reqData := [][]byte{[]byte("example.com"), []byte("/index.html")}
	reqBinder := crypto.CreateRequestBinding(hash, sk, reqData)

	redeemRequest := &BlindTokenRequest{
		Type:     "Redeem",
		Contents: [][]byte{tokens[0], reqBinder},
	}

	// Client -> (tokens[0], requestBinder) -> Server

	// Server
	// 4a. Check token redemption
	err = RedeemToken(*redeemRequest, []byte("example.com"), []byte("/index.html"), x)
	if err != nil {
		t.Fatal(err)
	}
}
