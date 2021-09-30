package kafka

import (
	"bytes"
	"fmt"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/btd"
	cbpServer "github.com/brave-intl/challenge-bypass-server/server"
	"github.com/rs/zerolog"
)

/*
 BlindedTokenIssuerHandler emits signed, blinded tokens based on provided blinded tokens.
 @TODO: It would be better for the Server implementation and the Kafka implementation of
 this behavior to share utility functions rather than passing an instance of the server
 as an argument here. That will require a bit of refactoring.
*/
func SignedBlindedTokenIssuerHandler(
	data []byte,
	resultTopic string,
	server *cbpServer.Server,
	logger *zerolog.Logger,
) {
	const (
		OK             = 0
		INVALID_ISSUER = 1
		ERROR          = 2
	)
	blindedTokenRequestSet, err := avroSchema.DeserializeSigningRequestSet(bytes.NewReader(data))
	if err != nil {
		logger.Error().Msg(fmt.Sprintf("Request %s: Failed Avro deserialization: %e", blindedTokenRequestSet.Request_id, err))
	}
	var blindedTokenResults []avroSchema.SigningResult
	for _, request := range blindedTokenRequestSet.Data {
		if request.Blinded_tokens == nil {
			logger.Error().Msg(fmt.Sprintf("Request %s: Empty request", blindedTokenRequestSet.Request_id))
			continue
		}

		if request.Issuer_cohort != 0 && request.Issuer_cohort != 1 {
			logger.Error().Msg(fmt.Sprintf("Request %s: Provided cohort is not supported: %d", blindedTokenRequestSet.Request_id, request.Issuer_cohort))
			continue
		}

		issuer, appErr := server.GetLatestIssuer(request.Issuer_type, int(request.Issuer_cohort))
		if appErr != nil {
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            INVALID_ISSUER,
				Associated_data:   request.Associated_data,
			})
			continue
		}

		var blindedTokens []*crypto.BlindedToken
		// Iterate over the provided tokens and create data structure from them,
		// grouping into a slice for approval
		for _, stringBlindedToken := range request.Blinded_tokens {
			blindedToken := crypto.BlindedToken{}
			blindedToken.UnmarshalText([]byte(stringBlindedToken))
			blindedTokens = append(blindedTokens, &blindedToken)
		}
		// @TODO: If one token fails they will all fail. Assess this behavior
		signedTokens, dleqProof, err := btd.ApproveTokens(blindedTokens, issuer.SigningKey)
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("Request %s: Could not approve new tokens: %e", blindedTokenRequestSet.Request_id, err))
			blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
				Signed_tokens:     nil,
				Issuer_public_key: "",
				Status:            ERROR,
				Associated_data:   request.Associated_data,
			})
			continue
		}
		marshaledDLEQProof, err := dleqProof.MarshalText()
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("Request %s: Could not marshal DLEQ proof: %e", blindedTokenRequestSet.Request_id, err))
			panic("Could not marshal DLEQ proof")
		}
		var marshaledTokens []string
		for _, token := range signedTokens {
			marshaledToken, err := token.MarshalText()
			if err != nil {
				logger.Error().Msg(fmt.Sprintf("Request %s: Could not marshal new tokens to bytes: %e", blindedTokenRequestSet.Request_id, err))
				panic("Could not marshal new tokens to bytes")
			}
			marshaledTokens = append(marshaledTokens, string(marshaledToken[:]))
		}
		publicKey := issuer.SigningKey.PublicKey()
		marshaledPublicKey, err := publicKey.MarshalText()
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("Request %s: Could not marshal signing key: %e", blindedTokenRequestSet.Request_id, err))
			panic("Could not marshal signing key")
		}
		blindedTokenResults = append(blindedTokenResults, avroSchema.SigningResult{
			Signed_tokens:     marshaledTokens,
			Proof:             string(marshaledDLEQProof),
			Issuer_public_key: string(marshaledPublicKey),
			Status:            OK,
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
		logger.Error().Msg(fmt.Sprintf("Request %s: Failed to serialize ResultSet: %s", blindedTokenRequestSet.Request_id, resultSet))
	}
	err = Emit(resultTopic, resultSetBuffer.Bytes(), logger)
	if err != nil {
		logger.Error().Msg(fmt.Sprintf("Request %s: Failed to emit results to topic %s: %e", blindedTokenRequestSet.Request_id, resultTopic, err))
	}
}
