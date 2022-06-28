// Code generated by github.com/actgardner/gogen-avro/v8. DO NOT EDIT.
/*
 * SOURCES:
 *     redeem_request.avsc
 *     redeem_result.avsc
 *     signing_request.avsc
 *     signing_result.avsc
 */
package generated

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/actgardner/gogen-avro/v9/compiler"
	"github.com/actgardner/gogen-avro/v9/vm"
	"github.com/actgardner/gogen-avro/v9/vm/types"
)

var _ = fmt.Printf

type SigningResult struct {
	Signed_tokens []string `json:"signed_tokens"`

	Issuer_public_key string `json:"issuer_public_key"`

	Proof string `json:"proof"`

	Status SigningResultStatus `json:"status"`
	// contains METADATA
	Associated_data Bytes `json:"associated_data"`
}

const SigningResultAvroCRC64Fingerprint = "!:\xad/\x80\x85\x98\xa9"

func NewSigningResult() SigningResult {
	r := SigningResult{}
	r.Signed_tokens = make([]string, 0)

	return r
}

func DeserializeSigningResult(r io.Reader) (SigningResult, error) {
	t := NewSigningResult()
	deser, err := compiler.CompileSchemaBytes([]byte(t.Schema()), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func DeserializeSigningResultFromSchema(r io.Reader, schema string) (SigningResult, error) {
	t := NewSigningResult()

	deser, err := compiler.CompileSchemaBytes([]byte(schema), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func writeSigningResult(r SigningResult, w io.Writer) error {
	var err error
	err = writeArrayString(r.Signed_tokens, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Issuer_public_key, w)
	if err != nil {
		return err
	}
	err = vm.WriteString(r.Proof, w)
	if err != nil {
		return err
	}
	err = writeSigningResultStatus(r.Status, w)
	if err != nil {
		return err
	}
	err = vm.WriteBytes(r.Associated_data, w)
	if err != nil {
		return err
	}
	return err
}

func (r SigningResult) Serialize(w io.Writer) error {
	return writeSigningResult(r, w)
}

func (r SigningResult) Schema() string {
	return "{\"fields\":[{\"name\":\"signed_tokens\",\"type\":{\"items\":{\"name\":\"signed_token\",\"type\":\"string\"},\"type\":\"array\"}},{\"name\":\"issuer_public_key\",\"type\":\"string\"},{\"name\":\"proof\",\"type\":\"string\"},{\"name\":\"status\",\"type\":{\"name\":\"SigningResultStatus\",\"symbols\":[\"ok\",\"invalid_issuer\",\"error\"],\"type\":\"enum\"}},{\"doc\":\"contains METADATA\",\"name\":\"associated_data\",\"type\":\"bytes\"}],\"name\":\"brave.cbp.SigningResult\",\"type\":\"record\"}"
}

func (r SigningResult) SchemaName() string {
	return "brave.cbp.SigningResult"
}

func (_ SigningResult) SetBoolean(v bool)    { panic("Unsupported operation") }
func (_ SigningResult) SetInt(v int32)       { panic("Unsupported operation") }
func (_ SigningResult) SetLong(v int64)      { panic("Unsupported operation") }
func (_ SigningResult) SetFloat(v float32)   { panic("Unsupported operation") }
func (_ SigningResult) SetDouble(v float64)  { panic("Unsupported operation") }
func (_ SigningResult) SetBytes(v []byte)    { panic("Unsupported operation") }
func (_ SigningResult) SetString(v string)   { panic("Unsupported operation") }
func (_ SigningResult) SetUnionElem(v int64) { panic("Unsupported operation") }

func (r *SigningResult) Get(i int) types.Field {
	switch i {
	case 0:
		r.Signed_tokens = make([]string, 0)

		return &ArrayStringWrapper{Target: &r.Signed_tokens}
	case 1:
		return &types.String{Target: &r.Issuer_public_key}
	case 2:
		return &types.String{Target: &r.Proof}
	case 3:
		return &SigningResultStatusWrapper{Target: &r.Status}
	case 4:
		return &BytesWrapper{Target: &r.Associated_data}
	}
	panic("Unknown field index")
}

func (r *SigningResult) SetDefault(i int) {
	switch i {
	}
	panic("Unknown field index")
}

func (r *SigningResult) NullField(i int) {
	switch i {
	}
	panic("Not a nullable field index")
}

func (_ SigningResult) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ SigningResult) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ SigningResult) Finalize()                        {}

func (_ SigningResult) AvroCRC64Fingerprint() []byte {
	return []byte(SigningResultAvroCRC64Fingerprint)
}

func (r SigningResult) MarshalJSON() ([]byte, error) {
	var err error
	output := make(map[string]json.RawMessage)
	output["signed_tokens"], err = json.Marshal(r.Signed_tokens)
	if err != nil {
		return nil, err
	}
	output["issuer_public_key"], err = json.Marshal(r.Issuer_public_key)
	if err != nil {
		return nil, err
	}
	output["proof"], err = json.Marshal(r.Proof)
	if err != nil {
		return nil, err
	}
	output["status"], err = json.Marshal(r.Status)
	if err != nil {
		return nil, err
	}
	output["associated_data"], err = json.Marshal(r.Associated_data)
	if err != nil {
		return nil, err
	}
	return json.Marshal(output)
}

func (r *SigningResult) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}

	var val json.RawMessage
	val = func() json.RawMessage {
		if v, ok := fields["signed_tokens"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Signed_tokens); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for signed_tokens")
	}
	val = func() json.RawMessage {
		if v, ok := fields["issuer_public_key"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Issuer_public_key); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for issuer_public_key")
	}
	val = func() json.RawMessage {
		if v, ok := fields["proof"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Proof); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for proof")
	}
	val = func() json.RawMessage {
		if v, ok := fields["status"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Status); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for status")
	}
	val = func() json.RawMessage {
		if v, ok := fields["associated_data"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Associated_data); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for associated_data")
	}
	return nil
}