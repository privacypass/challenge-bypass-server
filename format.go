package btd

import (
	"encoding/json"
)

// This is a transport format induced by internal systems. It should be
// irrelevant to third-party implementations.
// { bl_sig_req : b64-encoded request from client }
type BlindTokenRequestWrapper struct {
	Request []byte `json:"bl_sig_req"`
	Host    string `json:"host,omitempty"`
	Path    string `json:"http,omitempty"`
}

// { type : (Issue|Redeem), contents : list of b64-encoded blinded points }
type BlindTokenRequest struct {
	Type     ReqType  `json:"type"`
	Contents [][]byte `json:"contents"`
}

// Contains response to Issue request
// (incl. signed tokens, DLEQ proof and key version)
type IssuedTokenResponse struct {
	Sigs    [][]byte `json:"sigs"`
	Proof   []byte   `json:"proof"`
	Version string   `json:"version"`
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
