package btd

import (
	"log"
	"testing"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
)

var (
	testPayload = "Some test payload"
)

// Generates a small but well-formed ISSUE request for testing.
func makeTokenIssueRequest() ([]*crypto.Token, []*crypto.BlindedToken, error) {
	tokens := make([]*crypto.Token, 10)
	blindedTokens := make([]*crypto.BlindedToken, 10)
	for i := 0; i < len(tokens); i++ {
		token, err := crypto.RandomToken()
		if err != nil {
			return nil, nil, err
		}
		tokens[i] = token
		blindedTokens[i] = token.Blind()
	}

	return tokens, blindedTokens, nil
}

func makeTokenRedempRequest(sKey *crypto.SigningKey) (*crypto.TokenPreimage, *crypto.VerificationSignature, error) {
	// Client
	tokens, blindedTokens, err := makeTokenIssueRequest()
	if err != nil {
		return nil, nil, err
	}

	// Client -> (request) -> Server

	// Server
	// Sign the blind points
	signedTokens, dleqProof, err := ApproveTokens(blindedTokens, sKey)
	if err != nil {
		return nil, nil, err
	}

	// Client <- (signed blind tokens) <- Server

	// Verify DLEQ proof

	pKey := sKey.PublicKey()
	clientUnblindedTokens, err := dleqProof.VerifyAndUnblind(tokens, blindedTokens, signedTokens, pKey)
	if err != nil {
		return nil, nil, err
	}

	clientUnblindedToken := clientUnblindedTokens[0]

	// Redemption

	// client derives the shared key from the unblinded token
	clientvKey := clientUnblindedToken.DeriveVerificationKey()

	// client signs a message using the shared key
	clientSig, err := clientvKey.Sign(testPayload)
	if err != nil {
		return nil, nil, err
	}
	preimage := clientUnblindedToken.Preimage()

	return preimage, clientSig, nil
}

func TestTokenIssuance(t *testing.T) {
	_, blindedTokens, err := makeTokenIssueRequest()
	if err != nil {
		t.Fatalf("it's all borked")
	}

	sKey, err := crypto.RandomSigningKey()
	if err != nil {
		log.Fatalln(err)
		t.Fatal("couldn't generate the signing key")
	}
	pKey := sKey.PublicKey()

	signedTokens, dleqProof, err := ApproveTokens(blindedTokens, sKey)
	if err != nil {
		t.Fatal(err)
	}

	// Verify DLEQ proof

	proofVerfied, err := dleqProof.Verify(blindedTokens, signedTokens, pKey)
	if err != nil {
		t.Fatal(err)
	}
	if !proofVerfied {
		t.Fatal("DLEQ proof failed to verify")
	}
}

// Tests token redemption for multiple keys
func TestTokenRedemption(t *testing.T) {
	sKey1, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	sKey2, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	sKey3, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	// Redemption requests for all three keys
	preimage1, sig1, err := makeTokenRedempRequest(sKey1)
	if err != nil {
		t.Fatal(err)
	}
	preimage2, sig2, err := makeTokenRedempRequest(sKey2)
	if err != nil {
		t.Fatal(err)
	}
	preimage3, sig3, err := makeTokenRedempRequest(sKey3)
	if err != nil {
		t.Fatal(err)
	}

	// Only add two keys to check that the third redemption fails
	redeemKeys := []*crypto.SigningKey{sKey1, sKey2}

	// Server
	// Check valid token redemption
	err = VerifyTokenRedemption(preimage1, sig1, testPayload, redeemKeys)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyTokenRedemption(preimage2, sig2, testPayload, redeemKeys)
	if err != nil {
		t.Fatal(err)
	}
	// Check failed redemption
	err = VerifyTokenRedemption(preimage3, sig3, testPayload, redeemKeys)
	if err == nil {
		t.Fatal("This redemption should not be verified correctly.")
	}
}

func TestBadMAC(t *testing.T) {
	sKey, err := crypto.RandomSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	preimage, sig, err := makeTokenRedempRequest(sKey)
	if err != nil {
		t.Fatal(err)
	}

	// Server
	// Check bad token redemption
	err = VerifyTokenRedemption(preimage, sig, "bad payload", []*crypto.SigningKey{sKey})
	if err == nil {
		t.Fatal("No error occurred even though MAC should be bad")
	}
}
