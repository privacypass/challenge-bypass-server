package btd

import (
	stdcrypto "crypto"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/brave-intl/challenge-bypass-server/crypto"
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
)

// ApproveTokens applies the issuer's secret key to each token in the request.
// It returns an array of marshaled approved values along with a batch DLEQ proof.
func ApproveTokens(pretokens [][]byte, key []byte, G, H *crypto.Point) ([][]byte, []byte, error) {
	// Unmarshal the incoming blinded points
	// XXX: hardcoded curve assumption
	P, err := crypto.BatchUnmarshalPoints(elliptic.P256(), pretokens)
	if err != nil {
		return nil, nil, err
	}

	// Sign the points
	Q := make([]*crypto.Point, len(P))
	for i := 0; i < len(Q); i++ {
		if !P[i].IsOnCurve() {
			return nil, nil, ErrNotOnCurve
		}
		Q[i] = crypto.SignPoint(P[i], key)
	}

	// Generate batch DLEQ proof
	bp, err := crypto.NewBatchProof(stdcrypto.SHA256, G, H, P, Q, new(big.Int).SetBytes(key))
	if err != nil {
		return nil, nil, err
	}

	// Check that the proof is valid
	if !bp.Verify() {
		return nil, nil, ErrInvalidBatchProof
	}

	// Marshal the proof for response transmission
	bpData, err := bp.MarshalForResp()
	if err != nil {
		return nil, nil, err
	}

	// Batch marshal the signed curve points
	pointData, err := crypto.BatchMarshalPoints(Q)
	if err != nil {
		return nil, nil, err
	}

	// Returns an array containing marshaled points and batch DLEQ proof
	return pointData, bpData, nil
}

// RedeemToken checks a redemption request against the observed request data
// and MAC according a set of keys. keys keeps a set of private keys that
// are ever used to sign the token so we can rotate private key easily
// It also checks for double-spend. Returns nil on success and an
// error on failure.
func RedeemToken(tokenContents [][]byte, payload []byte, keys [][]byte) error {
	// XXX: hardcoded curve assumption
	curve := elliptic.P256()
	hash := stdcrypto.SHA256

	token, requestBinder := tokenContents[0], tokenContents[1]
	T, err := crypto.HashToCurve(curve, hash, token)
	if err != nil {
		return err
	}
	requestData := [][]byte{payload}

	var valid bool
	for _, key := range keys {
		sharedPoint := crypto.SignPoint(T, key)
		sharedKey := crypto.DeriveKey(hash, sharedPoint, token)

		valid = crypto.CheckRequestBinding(hash, sharedKey, requestBinder, requestData)

		if valid {
			break
		}
	}

	if !valid {
		return fmt.Errorf("%s, payload: %s", ErrInvalidMAC.Error(), payload)
	}

	return nil
}
