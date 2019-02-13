package btd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"

	"github.com/privacypass/challenge-bypass-server/crypto"
	"github.com/privacypass/challenge-bypass-server/metrics"
)

var (
	ErrInvalidMAC                = errors.New("binding MAC didn't match derived MAC")
	ErrNoDoubleSpendList         = errors.New("bloom filter is not initialized")
	ErrDoubleSpend               = errors.New("token was already spent")
	ErrTooManyTokens             = errors.New("ISSUE request contained too many tokens")
	ErrTooFewRedemptionArguments = errors.New("REDEEM request did not contain enough arguments")
	ErrUnexpectedRequestType     = errors.New("unexpected request type")
	ErrInvalidBatchProof         = errors.New("New batch proof for signed tokens is invalid")
	ErrNotOnCurve                = errors.New("One or more points not found on curve")

	// XXX: this is a fairly expensive piece of init
	SpentTokens = NewDoubleSpendList()
)

// Recovers the curve parameters that are sent by the client
// These specify the curve, hash and h2c method that they are using.
// If they are not specified (deprecated functionality) then we assume
// P256-SHA256-increment
func getClientCurveParams(contents [][]byte) (*crypto.CurveParams, error) {
	var curveParams *crypto.CurveParams
	var curveParamsBytes []byte
	if len(contents) == 3 {
		curveParamsBytes = contents[2]
		curveParams = &crypto.CurveParams{}
		err := json.Unmarshal(curveParamsBytes, curveParams)
		if err != nil {
			return nil, err
		}
	} else {
		curveParams = &crypto.CurveParams{Curve: "p256", Hash: "sha256", Method: "increment"}
	}

	return curveParams, nil
}

// ApproveTokens applies the issuer's secret key to each token in the request.
// It returns a struct of values containing:
// 		- signed tokens
// 		- a batched DLEQ proof
// 		- a string determining the version of the key that is being used
func ApproveTokens(req BlindTokenRequest, key []byte, keyVersion string, G, H *crypto.Point) (IssuedTokenResponse, error) {
	issueResponse := IssuedTokenResponse{}
	// We only support client curve params for redemption for now
	curveParams := &crypto.CurveParams{Curve: "p256", Hash: "sha256", Method: "increment"}
	h2cObj, err := curveParams.GetH2CObj()
	if err != nil {
		return issueResponse, err
	}

	// Unmarshal the incoming blinded points
	P, err := crypto.BatchUnmarshalPoints(h2cObj.Curve(), req.Contents)
	if err != nil {
		return issueResponse, err
	}

	// Sign the points
	Q := make([]*crypto.Point, len(P))
	for i := 0; i < len(Q); i++ {
		if !P[i].IsOnCurve() {
			return issueResponse, ErrNotOnCurve
		}
		Q[i] = crypto.SignPoint(P[i], key)
	}

	// Generate batch DLEQ proof
	bp, err := crypto.NewBatchProof(h2cObj.Hash(), G, H, P, Q, new(big.Int).SetBytes(key))
	if err != nil {
		return issueResponse, err
	}

	// Check that the proof is valid
	if !bp.Verify() {
		return issueResponse, ErrInvalidBatchProof
	}

	// Marshal the proof for response transmission
	bpData, err := bp.MarshalForResp()
	if err != nil {
		return issueResponse, err
	}

	// Batch marshal the signed curve points
	pointData, err := crypto.BatchMarshalPoints(Q)
	if err != nil {
		return issueResponse, err
	}

	issueResponse = IssuedTokenResponse{
		Sigs:    pointData,
		Proof:   bpData,
		Version: keyVersion,
	}

	// Returns an array containing marshaled points and batch DLEQ proof
	return issueResponse, nil
}

// RedeemToken checks a redemption request against the observed request data
// and MAC according a set of keys. keys keeps a set of private keys that
// are ever used to sign the token so we can rotate private key easily
// It also checks for double-spend. Returns nil on success and an
// error on failure.
func RedeemToken(req BlindTokenRequest, host, path []byte, keys [][]byte) error {
	// If the length is 3 then the curve parameters are provided by the client
	token, requestBinder := req.Contents[0], req.Contents[1]
	curveParams, err := getClientCurveParams(req.Contents)
	if err != nil {
		return err
	}
	h2cObj, err := curveParams.GetH2CObj()
	if err != nil {
		return err
	}

	T, err := h2cObj.HashToCurve(token)
	if err != nil {
		return err
	}
	requestData := [][]byte{host, path}

	var valid bool
	for _, key := range keys {
		sharedPoint := crypto.SignPoint(T, key)
		sharedKey := crypto.DeriveKey(h2cObj.Hash(), sharedPoint, token)
		valid = crypto.CheckRequestBinding(h2cObj.Hash(), sharedKey, requestBinder, requestData)
		if valid {
			break
		}
	}

	if !valid {
		metrics.CounterRedeemErrorVerify.Inc()
		return fmt.Errorf("%s, host: %s, path: %s, token: %v, request_binder: %v", ErrInvalidMAC.Error(), host, path, new(big.Int).SetBytes(token), new(big.Int).SetBytes(requestBinder))
	}

	doubleSpent := SpentTokens.CheckToken(token)
	if doubleSpent {
		metrics.CounterDoubleSpend.Inc()
		return ErrDoubleSpend
	}

	SpentTokens.AddToken(token)

	return nil
}

// HandleIssue deals with token issuance requests. It receives a slice of byte
// slices representing blinded curve points in the Contents field of a
// BlindTokenRequest. Approval consists of multiplying each point by a "secret
// key" that is a valid scalar for the underlying curve. After approval, it
// encodes the new points and writes them back to the client along with a
// batch DLEQ proof.
// Return nil on success, caller closes the connection.
func HandleIssue(conn *net.TCPConn, req BlindTokenRequest, key []byte, keyVersion string, G, H *crypto.Point, maxTokens int) error {
	if req.Type != ISSUE {
		metrics.CounterIssueErrorFormat.Inc()
		return ErrUnexpectedRequestType
	}
	tokenCount := len(req.Contents)
	if tokenCount > maxTokens {
		metrics.CounterIssueErrorFormat.Inc()
		return ErrTooManyTokens
	}

	// This also includes the dleq proof now
	issueResponse, err := ApproveTokens(req, key, keyVersion, G, H)
	if err != nil {
		return err
	}

	// Encodes the issue response as a JSON object
	jsonResp, err := json.Marshal(issueResponse)
	if err != nil {
		return err
	}

	// which we then wrap in another layer of base64 to avoid any transit or parsing mishaps
	base64Envelope := make([]byte, base64.StdEncoding.EncodedLen(len(jsonResp)))
	base64.StdEncoding.Encode(base64Envelope, jsonResp)

	// write back as "[b64 blob]" since the extension expects them formatted as
	// "signatures=[b64 blob]" in the HTTP response body
	conn.Write(base64Envelope)
	metrics.CounterIssueSuccess.Inc()
	return nil
}

// HandleRedeem deals with redemption requests. The Contents field of a
// redemption request should be a tuple of (token-preimage,
// HMAC_{sharedKey}(request-data)), where request-data is a concatenation of
// the other fields supplied in the request (currently Host header and the
// requested HTTP path). On successful validation, we write the ASCII string
// "success" back to the supplied connection and add the token preimage to a
// double-spend ledger. Internal semantics are still return nil on success,
// caller closes the connection.
func HandleRedeem(conn *net.TCPConn, req BlindTokenRequest, host, path string, keys [][]byte) error {
	if req.Type != REDEEM {
		metrics.CounterRedeemErrorFormat.Inc()
		return ErrUnexpectedRequestType
	}
	if len(req.Contents) < 2 {
		metrics.CounterRedeemErrorFormat.Inc()
		return ErrTooFewRedemptionArguments
	}

	if SpentTokens == nil {
		SpentTokens = NewDoubleSpendList()
	}

	// transform request data here if necessary

	err := RedeemToken(req, []byte(host), []byte(path), keys)
	if err != nil {
		return err
	}

	conn.Write([]byte("success"))
	metrics.CounterRedeemSuccess.Inc()
	return nil
}
