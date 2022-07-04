package kafka

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

// SignedTokenRedeemHandler BlindedTokenRedeemHandler emits payment tokens that correspond
// to the signed confirmation tokens provided.
func SignedTokenRedeemHandler(
	data []byte,
	producer *kafka.Writer,
	server *cbpServer.Server,
	logger *zerolog.Logger,
) error {
	const (
		redeemOk                  = 0
		redeemDuplicateRedemption = 1
		redeemUnverified          = 2
		redeemError               = 3
	)
	tokenRedeemRequestSet, err := avroSchema.DeserializeRedeemRequestSet(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("request %s: failed avro deserialization: %w", tokenRedeemRequestSet.Request_id, err)
	}
	defer func() {
		if recover() != nil {
			logger.Error().
				Err(fmt.Errorf("request %s: redeem attempt panicked", tokenRedeemRequestSet.Request_id)).
				Msg("signed token redeem handler")
		}
	}()
	var redeemedTokenResults []avroSchema.RedeemResult
	if len(tokenRedeemRequestSet.Data) > 1 {
		// NOTE: When we start supporting multiple requests we will need to review
		// errors and return values as well.
		return fmt.Errorf("request %s: data array unexpectedly contained more than a single message. this array is intended to make future extension easier, but no more than a single value is currently expected", tokenRedeemRequestSet.Request_id)
	}
	issuers, err := server.FetchAllIssuers()
	if err != nil {
		return fmt.Errorf("request %s: failed to fetch all issuers: %w", tokenRedeemRequestSet.Request_id, err)
	}
	for _, request := range tokenRedeemRequestSet.Data {
		var (
			verified             = false
			verifiedIssuer       = &cbpServer.Issuer{}
			verifiedCohort int32 = 0
		)
		if request.Public_key == "" {
			logger.Error().
				Err(fmt.Errorf("request %s: missing public key", tokenRedeemRequestSet.Request_id)).
				Msg("signed token redeem handler")
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          redeemError,
				Associated_data: request.Associated_data,
			})
			continue
		}

		if request.Token_preimage == "" || request.Signature == "" || request.Binding == "" {
			logger.Error().
				Err(fmt.Errorf("request %s: empty request", tokenRedeemRequestSet.Request_id)).
				Msg("signed token redeem handler")
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          redeemError,
				Associated_data: request.Associated_data,
			})
			continue
		}

		tokenPreimage := crypto.TokenPreimage{}
		err = tokenPreimage.UnmarshalText([]byte(request.Token_preimage))
		if err != nil {
			return fmt.Errorf("request %s: could not unmarshal text into preimage: %w",
				tokenRedeemRequestSet.Request_id, err)
		}
		verificationSignature := crypto.VerificationSignature{}
		err = verificationSignature.UnmarshalText([]byte(request.Signature))
		if err != nil {
			return fmt.Errorf("request %s: could not unmarshal text into verification signature: %w",
				tokenRedeemRequestSet.Request_id, err)
		}
		for _, issuer := range *issuers {
			if !issuer.ExpiresAt.IsZero() && issuer.ExpiresAt.Before(time.Now()) {
				continue
			}
			// Only attempt token verification with the issuer that was provided.
			issuerPublicKey := issuer.SigningKey.PublicKey()
			marshaledPublicKey, err := issuerPublicKey.MarshalText()
			if err != nil {
				return fmt.Errorf("request %s: could not unmarshal issuer public key into text: %w",
					tokenRedeemRequestSet.Request_id, err)
			}

			logger.Trace().
				Msgf("request %s: issuer: %s, request: %s", tokenRedeemRequestSet.Request_id,
					string(marshaledPublicKey), request.Public_key)

			if string(marshaledPublicKey) == request.Public_key {
				if err := btd.VerifyTokenRedemption(
					&tokenPreimage,
					&verificationSignature,
					request.Binding,
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
			logger.Error().
				Err(fmt.Errorf("request %s: could not verify that the token redemption is valid",
					tokenRedeemRequestSet.Request_id)).
				Msg("signed token redeem handler")
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          redeemUnverified,
				Associated_data: request.Associated_data,
			})
			continue
		} else {
			logger.Trace().Msgf("request %s: validated", tokenRedeemRequestSet.Request_id)
		}
		if err := server.RedeemToken(verifiedIssuer, &tokenPreimage, request.Binding); err != nil {
			logger.Error().Err(fmt.Errorf("request %s: token redemption failed: %w",
				tokenRedeemRequestSet.Request_id, err)).
				Msg("signed token redeem handler")
			if strings.Contains(err.Error(), "Duplicate") {
				logger.Error().Err(fmt.Errorf("request %s: duplicate redemption: %w",
					tokenRedeemRequestSet.Request_id, err)).
					Msg("signed token redeem handler")
				redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
					Issuer_name:     "",
					Issuer_cohort:   0,
					Status:          redeemDuplicateRedemption,
					Associated_data: request.Associated_data,
				})
			}
			logger.Error().Err(fmt.Errorf("request %s: could not mark token redemption",
				tokenRedeemRequestSet.Request_id)).
				Msg("signed token redeem handler")
			redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
				Issuer_name:     "",
				Issuer_cohort:   0,
				Status:          redeemError,
				Associated_data: request.Associated_data,
			})
			continue
		}
		logger.Trace().Msgf("request %s: redeemed", tokenRedeemRequestSet.Request_id)
		issuerName := verifiedIssuer.IssuerType
		redeemedTokenResults = append(redeemedTokenResults, avroSchema.RedeemResult{
			Issuer_name:     issuerName,
			Issuer_cohort:   verifiedCohort,
			Status:          redeemOk,
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
		return fmt.Errorf("request %s: failed to serialize result set: %w",
			tokenRedeemRequestSet.Request_id, err)
	}

	err = Emit(producer, resultSetBuffer.Bytes(), logger)
	if err != nil {
		return fmt.Errorf("request %s: failed to emit results to topic %s: %w",
			tokenRedeemRequestSet.Request_id, producer.Topic, err)
	}
	return nil
}
