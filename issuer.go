package btd

import (
	stdcrypto "crypto"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cloudflare/btd/crypto"
	"github.com/cloudflare/btd/metrics"
	"math/big"
	"net"
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

// ApproveTokens applies the issuer's secret key to each token in the request.
// It returns an array of marshaled approved values along with a batch DLEQ proof.
func ApproveTokens(req BlindTokenRequest, key []byte, G, H *crypto.Point) ([][]byte, error) {
	// Unmarshal the incoming blinded points
	// XXX: hardcoded curve assumption
	P, err := crypto.BatchUnmarshalPoints(elliptic.P256(), req.Contents)
	if err != nil {
		return nil, err
	}

	// Sign the points
	Q := make([]*crypto.Point, len(P))
	for i := 0; i < len(Q); i++ {
		if !P[i].IsOnCurve() {
			return nil, ErrNotOnCurve
		}
		Q[i] = crypto.SignPoint(P[i], key)
	}

	// Generate batch DLEQ proof
	bp, err := crypto.NewBatchProof(stdcrypto.SHA256, G, H, P, Q, new(big.Int).SetBytes(key))
	if err != nil {
		return nil, err
	}

	// Check that the proof is valid
	if !bp.Verify() {
		return nil, ErrInvalidBatchProof
	}

	// Marshal the proof for response transmission
	bpData, err := bp.MarshalForResp()
	if err != nil {
		return nil, err
	}

	// Batch marshal the signed curve points
	pointData, err := crypto.BatchMarshalPoints(Q)
	if err != nil {
		return nil, err
	}

	// Returns an array containing marshaled points and batch DLEQ proof
	return append(pointData, bpData), nil
}

// RedeemToken checks a redemption request against the observed request data
// and MAC. It also checks for double-spend. Returns nil on success and an
// error on failure.
func RedeemToken(req BlindTokenRequest, host, path, key []byte) error {
	// XXX: hardcoded curve assumption
	curve := elliptic.P256()
	hash := stdcrypto.SHA256

	token, requestBinder := req.Contents[0], req.Contents[1]
	T, err := crypto.HashToCurve(curve, hash, token)
	if err != nil {
		return err
	}
	sharedPoint := crypto.SignPoint(T, key)
	sharedKey := crypto.DeriveKey(hash, sharedPoint, token)

	requestData := [][]byte{host, path}
	valid := crypto.CheckRequestBinding(hash, sharedKey, requestBinder, requestData)

	if !valid {
		metrics.CounterRedeemErrorVerify.Inc()
		return fmt.Errorf("%s, host: %s, path: %s", ErrInvalidMAC.Error(), host, path)
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
func HandleIssue(conn *net.TCPConn, req BlindTokenRequest, key []byte, G, H *crypto.Point, maxTokens int) error {
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
	marshaledTokenList, err := ApproveTokens(req, key, G, H)
	if err != nil {
		return err
	}

	// EncodeByteArrays encodes the [][]byte as JSON
	jsonTokenList, err := EncodeByteArrays(marshaledTokenList)
	if err != nil {
		return err
	}

	// which we then wrap in another layer of base64 to avoid any transit or parsing mishaps
	base64Envelope := make([]byte, base64.StdEncoding.EncodedLen(len(jsonTokenList)))
	base64.StdEncoding.Encode(base64Envelope, jsonTokenList)

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
func HandleRedeem(conn *net.TCPConn, req BlindTokenRequest, host, path string, key []byte) error {
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

	err := RedeemToken(req, []byte(host), []byte(path), key)
	if err != nil {
		return err
	}

	conn.Write([]byte("success"))
	metrics.CounterRedeemSuccess.Inc()
	return nil
}
