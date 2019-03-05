package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/brave-intl/bat-go/middleware"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/go-chi/chi"
	uuid "github.com/satori/go.uuid"
)

var handler http.Handler

var accessToken string

func init() {
	os.Setenv("ENV", "production")

	accessToken = uuid.NewV4().String()
	middleware.TokenList = []string{accessToken}

	srv := &Server{}

	err := srv.InitDbConfig()
	if err != nil {
		panic(err)
	}

	handler = chi.ServerBaseContext(srv.setupRouter(SetupLogger(context.Background())))
}

func TestPing(t *testing.T) {
	server := httptest.NewServer(handler)
	defer server.Close()
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Received non-200 response: %d\n", resp.StatusCode)
	}
	expected := "."
	actual, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if expected != string(actual) {
		t.Errorf("Expected the message '%s'\n", expected)
	}
}

func request(method string, URL string, payload io.Reader) (*http.Response, error) {
	var req *http.Request
	var err error
	if payload != nil {
		req, err = http.NewRequest(method, URL, payload)
	} else {
		req, err = http.NewRequest(method, URL, nil)
	}
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Received non-200 response: %d", resp.StatusCode)
	}
	return resp, nil
}

func TestIssueRedeem(t *testing.T) {
	issuerType := "test"
	msg := "test message"

	server := httptest.NewServer(handler)
	defer server.Close()

	payload := fmt.Sprintf(`{"name":"%s", "max_tokens":100}`, issuerType)
	createIssuerURL := fmt.Sprintf("%s/v1/issuer/", server.URL)
	_, err := request("POST", createIssuerURL, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		t.Fatal(err)
	}

	issuerURL := fmt.Sprintf("%s/v1/issuer/%s", server.URL, issuerType)
	resp, err := request("GET", issuerURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var issuerResp IssuerResponse
	err = json.Unmarshal(body, &issuerResp)
	if err != nil {
		t.Fatal(err)
	}

	if issuerResp.PublicKey == nil {
		t.Fatal("Public key was missing")
	}

	publicKey := issuerResp.PublicKey

	token, err := crypto.RandomToken()
	if err != nil {
		t.Fatal(err)
	}

	blindedToken := token.Blind()
	blindedTokenText, err := blindedToken.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	payload = fmt.Sprintf(`{"blinded_tokens":["%s"]}}`, blindedTokenText)
	issueURL := fmt.Sprintf("%s/v1/blindedToken/%s", server.URL, issuerType)
	resp, err = request("POST", issueURL, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		t.Fatal(err)
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var decodedResp BlindedTokenIssueResponse
	err = json.Unmarshal(body, &decodedResp)
	if err != nil {
		t.Fatal(err)
	}

	if decodedResp.BatchProof == nil || len(decodedResp.SignedTokens) != 1 {
		t.Fatal("Batch proof or signed tokens not returned")
	}

	unblindedTokens, err := decodedResp.BatchProof.VerifyAndUnblind([]*crypto.Token{token}, []*crypto.BlindedToken{blindedToken}, decodedResp.SignedTokens, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	unblindedToken := unblindedTokens[0]

	vKey := unblindedToken.DeriveVerificationKey()

	sig, err := vKey.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	sigText, err := sig.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	preimage := unblindedToken.Preimage()
	preimageText, err := preimage.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	payload = fmt.Sprintf(`{"t":"%s", "signature":"%s", "payload":"%s"}`, preimageText, sigText, msg)
	redeemURL := fmt.Sprintf("%s/v1/blindedToken/%s/redemption/", server.URL, issuerType)

	_, err = request("POST", redeemURL, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		t.Fatal(err)
	}
}
