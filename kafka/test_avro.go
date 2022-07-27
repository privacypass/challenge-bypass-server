package kafka

import (
	"bytes"
	"testing"

	avroSchema "github.com/brave-intl/challenge-bypass-server/avro/generated"
)

func TestOriginalAvroNewSchema(t *testing.T) {

	buf := bytes.NewBuffer([]byte{})

	orig := &avroSchema.OriginalSigningResult{
		Signed_tokens:     []string{"signed token"},
		Issuer_public_key: "issuer public key",
		Proof:             "proof",
	}

	if err := orig.Serialize(buf); err != nil {
		t.Error("failed to serialize original message type: ", err)
		return
	}

	newSigningResult, err := avroSchema.DeserializeOriginalSigningResult(buf)
	if err != nil {
		t.Error("failed to deserialize into new message type: ", err)
		return
	}
	if newSigningResult.Proof != "proof" {
		t.Error("invalid attribute in signing result: ", newSigningResult.Proof)
		return
	}
}
