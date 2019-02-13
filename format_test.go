package btd

import (
	"bytes"
	"testing"

	"github.com/privacypass/challenge-bypass-server/crypto"
)

// Tests that token arrays can be encoded correctly for all curve settings
func TestEncodeIncrement(t *testing.T) { crypto.HandleTest(t, "increment", encodeTokenArray) }
func TestEncodeSWU(t *testing.T)       { crypto.HandleTest(t, "swu", encodeTokenArray) }
func encodeTokenArray(t *testing.T, h2cObj crypto.H2CObject) {
	tokens := make([][]byte, 2)
	for i := 0; i < len(tokens); i++ {
		token, _, _, err := crypto.CreateBlindToken(h2cObj)
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = token
	}

	data, err := EncodeByteArrays(tokens)
	if err != nil {
		t.Error(err)
	}
	// encoding overhead for 2 elements
	// 2 for [ ]
	// 2 for each element's " "
	// 2/2 for each ,
	// For two elements: 2 + 2*2 + 2/2 = 7
	// len(base64([32]byte)) = 44 * 2 = 88 + 7 = 95
	if len(data) != 95 {
		t.Errorf("unexpected encoding size %d expected 95", len(data))
	}

	values, err := DecodeByteArrays(data)
	if err != nil {
		t.Error(err)
	}

	if len(tokens) != len(values) {
		t.Errorf("decoded array was a different length")
	}

	for i := 0; i < len(tokens); i++ {
		if !bytes.Equal(tokens[i], values[i]) {
			t.Errorf("json decoding is broken")
			break
		}
	}
}
