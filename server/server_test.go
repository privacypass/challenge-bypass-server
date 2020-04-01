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
	"github.com/stretchr/testify/suite"
)

type ServerTestSuite struct {
	suite.Suite
	handler     http.Handler
	accessToken string
	srv         *Server
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

func (suite *ServerTestSuite) SetupSuite() {
	os.Setenv("ENV", "production")

	suite.accessToken = uuid.NewV4().String()
	middleware.TokenList = []string{suite.accessToken}

	suite.srv = &Server{}

	err := suite.srv.InitDbConfig()
	suite.Require().NoError(err, "Failed to setup db conn")

	suite.handler = chi.ServerBaseContext(suite.srv.setupRouter(SetupLogger(context.Background())))
}

func (suite *ServerTestSuite) SetupTest() {
	tables := []string{"issuers", "redemptions"}

	for _, table := range tables {
		_, err := suite.srv.db.Exec("delete from " + table)
		suite.Require().NoError(err, "Failed to get clean table")
	}
}

func (suite *ServerTestSuite) TestPing() {
	server := httptest.NewServer(suite.handler)
	defer server.Close()
	resp, err := http.Get(server.URL)
	suite.Require().NoError(err, "Ping request must succeed")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	expected := "."
	actual, err := ioutil.ReadAll(resp.Body)
	suite.Assert().NoError(err, "Reading response body should succeed")
	suite.Assert().Equal(expected, string(actual), "Message should match")
}

func (suite *ServerTestSuite) request(method string, URL string, payload io.Reader) (*http.Response, error) {
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

	req.Header.Add("Authorization", "Bearer "+suite.accessToken)
	req.Header.Add("Content-Type", "application/json")

	return http.DefaultClient.Do(req)
}

func (suite *ServerTestSuite) createIssuer(serverURL string, issuerType string) *crypto.PublicKey {
	payload := fmt.Sprintf(`{"name":"%s", "max_tokens":100}`, issuerType)
	createIssuerURL := fmt.Sprintf("%s/v1/issuer/", serverURL)
	resp, err := suite.request("POST", createIssuerURL, bytes.NewBuffer([]byte(payload)))
	suite.Require().NoError(err, "Issuer creation must succeed")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	issuerURL := fmt.Sprintf("%s/v1/issuer/%s", serverURL, issuerType)
	resp, err = suite.request("GET", issuerURL, nil)
	suite.Require().NoError(err, "Issuer fetch must succeed")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	suite.Require().NoError(err, "Issuer fetch body read must succeed")

	var issuerResp issuerResponse
	err = json.Unmarshal(body, &issuerResp)
	suite.Require().NoError(err, "Issuer fetch body unmarshal must succeed")

	suite.Require().NotEqual(issuerResp.PublicKey, nil, "Public key was missing")

	suite.Require().NotEqual(issuerResp.ID, "", "ID was missing")

	return issuerResp.PublicKey
}

func (suite *ServerTestSuite) createToken(serverURL string, issuerType string, publicKey *crypto.PublicKey) *crypto.UnblindedToken {
	return suite.createTokens(serverURL, issuerType, publicKey, 1)[0]
}
func (suite *ServerTestSuite) createTokens(serverURL string, issuerType string, publicKey *crypto.PublicKey, numTokens int) []*crypto.UnblindedToken {
	tokens := make([]*crypto.Token, numTokens)
	blindedTokens := make([]*crypto.BlindedToken, numTokens)

	for i := 0; i < numTokens; i++ {
		token, err := crypto.RandomToken()
		suite.Require().NoError(err, "Must be able to generate random token")
		tokens[i] = token

		blindedToken := token.Blind()
		suite.Require().NoError(err, "Must be able to blind token")
		blindedTokens[i] = blindedToken
	}

	blindedTokenText, err := json.Marshal(blindedTokens)
	suite.Require().NoError(err, "Must be able to marshal blinded tokens")

	payload := fmt.Sprintf(`{"blinded_tokens":%s}}`, blindedTokenText)
	issueURL := fmt.Sprintf("%s/v1/blindedToken/%s", serverURL, issuerType)
	resp, err := suite.request("POST", issueURL, bytes.NewBuffer([]byte(payload)))
	suite.Require().NoError(err, "Token signing must succeed")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	body, err := ioutil.ReadAll(resp.Body)
	suite.Require().NoError(err, "Token signing body read must succeed")

	var decodedResp blindedTokenIssueResponse
	err = json.Unmarshal(body, &decodedResp)
	suite.Require().NoError(err, "Token signing body unmarshal must succeed")

	suite.Require().NotEqual(nil, decodedResp.BatchProof, "Batch proof was missing")
	suite.Require().Equal(numTokens, len(decodedResp.SignedTokens), "Signed tokens were missing")

	unblindedTokens, err := decodedResp.BatchProof.VerifyAndUnblind(tokens, blindedTokens, decodedResp.SignedTokens, publicKey)
	suite.Require().NoError(err, "Batch verification and token unblinding must succeed")

	return unblindedTokens
}

func (suite *ServerTestSuite) prepareRedemption(unblindedToken *crypto.UnblindedToken, msg string) (preimageText []byte, sigText []byte) {
	vKey := unblindedToken.DeriveVerificationKey()

	sig, err := vKey.Sign(msg)
	suite.Require().NoError(err, "Must be able to sign message")
	sigText, err = sig.MarshalText()
	suite.Require().NoError(err, "Must be able to marshal signature")

	preimage := unblindedToken.Preimage()
	preimageText, err = preimage.MarshalText()
	suite.Require().NoError(err, "Must be able to marshal preimage")

	return
}
func (suite *ServerTestSuite) attemptRedeem(serverURL string, preimageText []byte, sigText []byte, issuerType string, msg string) (*http.Response, error) {
	payload := fmt.Sprintf(`{"t":"%s", "signature":"%s", "payload":"%s"}`, preimageText, sigText, msg)
	redeemURL := fmt.Sprintf("%s/v1/blindedToken/%s/redemption/", serverURL, issuerType)

	return suite.request("POST", redeemURL, bytes.NewBuffer([]byte(payload)))
}

func (suite *ServerTestSuite) TestIssueRedeem() {
	issuerType := "test"
	msg := "test message"

	server := httptest.NewServer(suite.handler)
	defer server.Close()

	publicKey := suite.createIssuer(server.URL, issuerType)
	unblindedToken := suite.createToken(server.URL, issuerType, publicKey)
	preimageText, sigText := suite.prepareRedemption(unblindedToken, msg)

	resp, err := suite.attemptRedeem(server.URL, preimageText, sigText, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusOK, resp.StatusCode, "Attempted redemption request should succeed")

	resp, err = suite.attemptRedeem(server.URL, preimageText, sigText, issuerType, msg)
	suite.Assert().NoError(err, "HTTP Request should complete")
	suite.Assert().Equal(http.StatusConflict, resp.StatusCode, "Attempted duplicate redemption request should fail")
}
