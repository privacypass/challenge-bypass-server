package btd

import (
	"encoding/json"
)

// Array of base64-encoded curve points
type IssuedTokenResponse struct {
	MarshaledPoints [][]byte
}

type ReqType string

var (
	ISSUE  ReqType = "Issue"
	REDEEM ReqType = "Redeem"
)

// EncodeByteArrays turns [][]byte into JSON with base64-encoded byte blobs.
func EncodeByteArrays(values [][]byte) ([]byte, error) {
	return json.Marshal(values)
}

// DecodeByteArrays decodes JSON of the fromat produced by EncodeByteArrays.
func DecodeByteArrays(encoded []byte) ([][]byte, error) {
	var values [][]byte
	err := json.Unmarshal(encoded, &values)
	return values, err
}

func MarshalRequest(request interface{}) ([]byte, error) {
	jsonRequest, err := json.Marshal(request)
	return jsonRequest, err
}
