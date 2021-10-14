package kafka

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/rs/zerolog"
)

/*
 BlindedTokenRedeemHandler emits payment tokens that correspond to the signed confirmation
 tokens provided.
*/
func SignedTokenRedeemHandler(
	data []byte,
	resultTopic string,
	server *cbpServer.Server,
	logger *zerolog.Logger,
) error {
	const (
		OK                   = 0
		DUPLICATE_REDEMPTION = 1
		UNVERIFIED           = 2
		ERROR                = 3
	)
	tokenRedeemRequestSet, err := avroSchema.DeserializeRedeemRequestSet(bytes.NewReader(data))
	if err != nil {
		return errors.New(fmt.Sprintf("Request %s: Failed Avro deserialization: %e", tokenRedeemRequestSet.Request_id, err))
	}
	var redeemedTokenResults []avroSchema.RedeemResult
	if len(tokenRedeemRequestSet.Data) > 1 {
		// NOTE: When we start supporting multiple requests we will need to review
		// errors and return values as well.
		return errors.New(fmt.Sprintf("Request %s: Data array unexpectedly contained more than a single message. This array is intended to make future extension easier, but no more than a single value is currently expected.", tokenRedeemRequestSet.Request_id))
	}
	for _, request := range tokenRedeemRequestSet.Data {
		var (
			verified             = false
			verifiedIssuer       = &cbpServer.Issuer{}
			verifiedCohort int32 = 0
		)
		if request.Public_key == "" {
			logger.Error().Msg(fmt.Sprintf("Request %s: Missing public key", tokenRedeemRequestSet.Request_id))
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          ERROR,
				Associated_data: request.Associated_data,
			})
			continue
		}

		if request.Token_preimage == "" || request.Signature == "" || request.Binding == "" {
			logger.Error().Msg(fmt.Sprintf("Request %s: Empty request", tokenRedeemRequestSet.Request_id))
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          ERROR,
				Associated_data: request.Associated_data,
			})
			continue
		}

		issuers, err := server.FetchAllIssuers()
		if err != nil {
			return errors.New(fmt.Sprintf("Request %s: Invalid issuer: %e", tokenRedeemRequestSet.Request_id, err))
		}
		tokenPreimage := crypto.TokenPreimage{}
		err = tokenPreimage.UnmarshalText([]byte(request.Token_preimage))
		if err != nil {
			return errors.New(fmt.Sprintf("Request %s: Could not unmarshal text into preimage: %e", tokenRedeemRequestSet.Request_id, err))
		}
		verificationSignature := crypto.VerificationSignature{}
		err = verificationSignature.UnmarshalText([]byte(request.Signature))
		if err != nil {
			return errors.New(fmt.Sprintf("Request %s: Could not unmarshal text into verification signature: %e", tokenRedeemRequestSet.Request_id, err))
		}
		for _, issuer := range *issuers {
			if !issuer.ExpiresAt.IsZero() && issuer.ExpiresAt.Before(time.Now()) {
				continue
			}
			// Only attempt token verification with the issuer that was provided.
			issuerPublicKey := issuer.SigningKey.PublicKey()
			marshaledPublicKey, err := issuerPublicKey.MarshalText()
			if err != nil {
				return errors.New(fmt.Sprintf("Request %s: Could not unmarshal issuer private key into text: %e", tokenRedeemRequestSet.Request_id, err))
			}
			if string(marshaledPublicKey) == request.Public_key {
				if err := btd.VerifyTokenRedemption(
					&tokenPreimage,
					&verificationSignature,
					string(request.Binding),
					[]*crypto.SigningKey{issuer.SigningKey},
				); err != nil {
					verified = false
				} else {
					verified = true
					verifiedIssuer = &issuer
					verifiedCohort = int32(issuer.IssuerCohort)
					break
				}
			}
		}

		if !verified {
			logger.Error().Msg(fmt.Sprintf("Request %s: Could not verify that the token redemption is valid", tokenRedeemRequestSet.Request_id))
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          UNVERIFIED,
				Associated_data: request.Associated_data,
			})
			continue
		}
		if err := server.RedeemToken(verifiedIssuer, &tokenPreimage, string(request.Binding)); err != nil {
			if strings.Contains(err.Error(), "Duplicate") {
				logger.Error().Msg(fmt.Sprintf("Request %s: Duplicate redemption: %e", tokenRedeemRequestSet.Request_id, err))
				redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
					Issuer_name:     "",
					Issuer_cohort:   0,
					Status:          DUPLICATE_REDEMPTION,
					Associated_data: request.Associated_data,
				})
			}
			logger.Error().Msg(fmt.Sprintf("Request %s: Could not mark token redemption", tokenRedeemRequestSet.Request_id))
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          ERROR,
				Associated_data: request.Associated_data,
			})
			continue
		}
		issuerName := verifiedIssuer.IssuerType
		redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
			Issuer_name:     issuerName,
			Issuer_cohort:   verifiedCohort,
			Status:          OK,
			Associated_data: request.Associated_data,
		})
	}
	resultSet := avroSchema.RedeemResultSet{
		Request_id: tokenRedeemRequestSet.Request_id,
		Data:       redeemedTokenResults,
	}
	var resultSetBuffer bytes.Buffer
	err = resultSet.Serialize(&resultSetBuffer)
	if err != nil {
		return errors.New(fmt.Sprintf("Request %s: Failed to serialize ResultSet: %e", tokenRedeemRequestSet.Request_id, err))
	}

	err = Emit(resultTopic, resultSetBuffer.Bytes(), logger)
	if err != nil {
		return errors.New(fmt.Sprintf("Request %s: Failed to emit results to topic %s: %e", tokenRedeemRequestSet.Request_id, resultTopic, err))
	}
	return nil
}
