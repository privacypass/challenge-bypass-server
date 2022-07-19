package kafka

import (
	"bytes"
	"fmt"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/rs/zerolog"
	kafka "github.com/segmentio/kafka-go"
)

// SignedBlindedTokenIssuerHandler emits signed, blinded tokens based on provided blinded tokens.
// @TODO: It would be better for the Server implementation and the Kafka implementation of
// this behavior to share utility functions rather than passing an instance of the server
// as an argument here. That will require a bit of refactoring.
func SignedBlindedTokenIssuerHandler(
	data []byte,
	producer *kafka.Writer,
	server *cbpServer.Server,
	logger *zerolog.Logger,
) error {
	const (
		issuerOk      = 0
		issuerInvalid = 1
		issuerError   = 2
	)
	blindedTokenRequestSet, err := avroSchema.DeserializeSigningRequestSet(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("request %s: failed avro deserialization: %w", blindedTokenRequestSet.Request_id, err)
	}
	var blindedTokenResults []avroSchema.SigningResult
	if len(blindedTokenRequestSet.Data) > 1 {
		// NOTE: When we start supporting multiple requests we will need to review
		// errors and return values as well.
		return fmt.Errorf("request %s: data array unexpectedly contained more than a single message. this array is intended to make future extension easier, but no more than a single value is currently expected",
			blindedTokenRequestSet.Request_id)
	}
	for _, request := range blindedTokenRequestSet.Data {
		if request.Blinded_tokens == nil {
			logger.Error().Msgf("request %s: empty request", blindedTokenRequestSet.Request_id)
			continue
		}

		issuer, appErr := server.GetLatestIssuer(request.Issuer_type, int(request.Issuer_cohort))
		if appErr != nil {
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            issuerInvalid,
				Associated_data:   request.Associated_data,
			})
			continue
		}

		var blindedTokens []*crypto.BlindedToken
		// Iterate over the provided tokens and create data structure from them,
		// grouping into a slice for approval
		for _, stringBlindedToken := range request.Blinded_tokens {
			blindedToken := crypto.BlindedToken{}
			err := blindedToken.UnmarshalText([]byte(stringBlindedToken))
			if err != nil {
				logger.Error().
					Err(fmt.Errorf("request %s: failed to unmarshal blinded tokens: %w",
						blindedTokenRequestSet.Request_id, err)).
					Msg("signed blinded token issuer handler")
				blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
					Signed_tokens:     nil,
					Issuer_public_key: "",
					Status:            issuerError,
					Associated_data:   request.Associated_data,
				})
				continue
			}
			blindedTokens = append(blindedTokens, &blindedToken)
		}
		// @TODO: If one token fails they will all fail. Assess this behavior
		signedTokens, dleqProof, err := btd.ApproveTokens(blindedTokens, issuer.SigningKey)
		if err != nil {
			logger.Error().
				Err(fmt.Errorf("request %s: could not approve new tokens: %w",
					blindedTokenRequestSet.Request_id, err)).
				Msg("signed blinded token issuer handler")
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            issuerError,
				Associated_data:   request.Associated_data,
			})
			continue
		}
		marshaledDLEQProof, err := dleqProof.MarshalText()
		if err != nil {
			return fmt.Errorf("request %s: could not marshal dleq proof: %w", blindedTokenRequestSet.Request_id, err)
		}
		var marshaledTokens []string
		for _, token := range signedTokens {
			marshaledToken, err := token.MarshalText()
			if err != nil {
				return fmt.Errorf("request %s: could not marshal new tokens to bytes: %w",
					blindedTokenRequestSet.Request_id, err)
			}
			marshaledTokens = append(marshaledTokens, string(marshaledToken[:]))
		}
		publicKey := issuer.SigningKey.PublicKey()
		marshaledPublicKey, err := publicKey.MarshalText()
		if err != nil {
			return fmt.Errorf("request %s: could not marshal signing key: %w",
				blindedTokenRequestSet.Request_id, err)
		}
		blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
			Signed_tokens:     marshaledTokens,
			Proof:             string(marshaledDLEQProof),
			Issuer_public_key: string(marshaledPublicKey),
			Status:            issuerOk,
			Associated_data:   request.Associated_data,
		})
	}
	resultSet := avroSchema.SigningResultSet{
		Request_id: blindedTokenRequestSet.Request_id,
		Data:       blindedTokenResults,
	}
	var resultSetBuffer bytes.Buffer
	err = resultSet.Serialize(&resultSetBuffer)
	if err != nil {
		return fmt.Errorf("request %s: failed to serialize result set: %s: %w",
			blindedTokenRequestSet.Request_id, resultSet, err)
	}
	err = Emit(producer, resultSetBuffer.Bytes(), logger)
	if err != nil {
		return fmt.Errorf("request %s: failed to emit results to topic %s: %w",
			blindedTokenRequestSet.Request_id, producer.Topic, err)
	}
	return nil
}
