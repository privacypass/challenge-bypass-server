package kafka

import (
	"bytes"
	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
	"github.com/brave-intl/challenge-bypass-server/utils/test"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

// Tests v2 adds new fields validTo, validFrom and BlindedTokens.
func TestSchemaCompatability_SigningResult_V2ToV1(t *testing.T) {
	v2 := &avroSchema.SigningResultV2{
		Signed_tokens:     []string{test.RandomString()},
		Issuer_public_key: test.RandomString(),
		Proof:             test.RandomString(),
		Valid_from: &avroSchema.UnionNullString{String: time.Now().String(),
			UnionType: avroSchema.UnionNullStringTypeEnumString},
		Valid_to: &avroSchema.UnionNullString{String: time.Now().String(),
			UnionType: avroSchema.UnionNullStringTypeEnumString},
		Status:          1,
		Associated_data: []byte{},
		Blinded_tokens:  []string{test.RandomString()},
	}

	var buf bytes.Buffer
	err := v2.Serialize(&buf)
	assert.NoError(t, err)

	v1, err := avroSchema.DeserializeSigningResultV1(&buf)
	assert.NoError(t, err)

	assert.Equal(t, v2.Signed_tokens, v1.Signed_tokens)
	assert.Equal(t, v2.Issuer_public_key, v1.Issuer_public_key)
	assert.Equal(t, v2.Proof, v1.Proof)
	assert.Equal(t, v2.Status.String(), v1.Status.String())
}

//// Tests v2 consumers reading v1 messages.
//func TestSchemaCompatability_SigningResult_V1ToV2(t *testing.T) {
//	v1 := &avroSchema.SigningResultV1{
//		Signed_tokens:     []string{test.RandomString()},
//		Issuer_public_key: test.RandomString(),
//		Proof:             test.RandomString(),
//		Status:            0,
//		Associated_data:   []byte{},
//	}
//
//	var buf bytes.Buffer
//	err := v1.Serialize(&buf)
//	assert.NoError(t, err)
//
//	v2, err := avroSchema.DeserializeSigningResultV2(&buf)
//	assert.NoError(t, err)
//
//	assert.Equal(t, v1.Signed_tokens, v2.Signed_tokens)
//	assert.Equal(t, v1.Issuer_public_key, v2.Issuer_public_key)
//	assert.Equal(t, v1.Proof, v2.Proof)
//	assert.Equal(t, v1.Status.String(), v2.Status.String())
//	//assert.Nil(t, v2.Valid_to)
//	//assert.Nil(t, v2.Valid_from)
//	assert.Empty(t, v2.Blinded_tokens)
//}
