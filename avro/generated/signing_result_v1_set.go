// Code generated by github.com/actgardner/gogen-avro/v10. DO NOT EDIT.
/*
 * SOURCES:
 *     redeem_request.avsc
 *     redeem_result.avsc
 *     signing_request.avsc
 *     signing_result_v1.avsc
 *     signing_result_v2.avsc
 */
package generated

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/actgardner/gogen-avro/v10/compiler"
	"github.com/actgardner/gogen-avro/v10/vm"
	"github.com/actgardner/gogen-avro/v10/vm/types"
)

var _ = fmt.Printf

// Top level request containing the data to be processed, as well as any top level metadata for this message.
type SigningResultV1Set struct {
	Request_id string `json:"request_id"`

	Data []SigningResultV1 `json:"data"`
}

const SigningResultV1SetAvroCRC64Fingerprint = "H\x05k\x90\xaf\xb5z\xec"

func NewSigningResultV1Set() SigningResultV1Set {
	r := SigningResultV1Set{}
	r.Data = make([]SigningResultV1, 0)

	return r
}

func DeserializeSigningResultV1Set(r io.Reader) (SigningResultV1Set, error) {
	t := NewSigningResultV1Set()
	deser, err := compiler.CompileSchemaBytes([]byte(t.Schema()), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func DeserializeSigningResultV1SetFromSchema(r io.Reader, schema string) (SigningResultV1Set, error) {
	t := NewSigningResultV1Set()

	deser, err := compiler.CompileSchemaBytes([]byte(schema), []byte(t.Schema()))
	if err != nil {
		return t, err
	}

	err = vm.Eval(r, deser, &t)
	return t, err
}

func writeSigningResultV1Set(r SigningResultV1Set, w io.Writer) error {
	var err error
	err = vm.WriteString(r.Request_id, w)
	if err != nil {
		return err
	}
	err = writeArraySigningResultV1(r.Data, w)
	if err != nil {
		return err
	}
	return err
}

func (r SigningResultV1Set) Serialize(w io.Writer) error {
	return writeSigningResultV1Set(r, w)
}

func (r SigningResultV1Set) Schema() string {
	return "{\"doc\":\"Top level request containing the data to be processed, as well as any top level metadata for this message.\",\"fields\":[{\"name\":\"request_id\",\"type\":\"string\"},{\"name\":\"data\",\"type\":{\"items\":{\"fields\":[{\"name\":\"signed_tokens\",\"type\":{\"items\":{\"name\":\"signed_token\",\"type\":\"string\"},\"type\":\"array\"}},{\"name\":\"issuer_public_key\",\"type\":\"string\"},{\"name\":\"proof\",\"type\":\"string\"},{\"name\":\"status\",\"type\":{\"name\":\"SigningResultV1Status\",\"symbols\":[\"ok\",\"invalid_issuer\",\"error\"],\"type\":\"enum\"}},{\"doc\":\"contains METADATA\",\"name\":\"associated_data\",\"type\":\"bytes\"}],\"name\":\"SigningResultV1\",\"namespace\":\"brave.cbp\",\"type\":\"record\"},\"type\":\"array\"}}],\"name\":\"brave.cbp.SigningResultV1Set\",\"type\":\"record\"}"
}

func (r SigningResultV1Set) SchemaName() string {
	return "brave.cbp.SigningResultV1Set"
}

func (_ SigningResultV1Set) SetBoolean(v bool)    { panic("Unsupported operation") }
func (_ SigningResultV1Set) SetInt(v int32)       { panic("Unsupported operation") }
func (_ SigningResultV1Set) SetLong(v int64)      { panic("Unsupported operation") }
func (_ SigningResultV1Set) SetFloat(v float32)   { panic("Unsupported operation") }
func (_ SigningResultV1Set) SetDouble(v float64)  { panic("Unsupported operation") }
func (_ SigningResultV1Set) SetBytes(v []byte)    { panic("Unsupported operation") }
func (_ SigningResultV1Set) SetString(v string)   { panic("Unsupported operation") }
func (_ SigningResultV1Set) SetUnionElem(v int64) { panic("Unsupported operation") }

func (r *SigningResultV1Set) Get(i int) types.Field {
	switch i {
	case 0:
		w := types.String{Target: &r.Request_id}

		return w

	case 1:
		r.Data = make([]SigningResultV1, 0)

		w := ArraySigningResultV1Wrapper{Target: &r.Data}

		return w

	}
	panic("Unknown field index")
}

func (r *SigningResultV1Set) SetDefault(i int) {
	switch i {
	}
	panic("Unknown field index")
}

func (r *SigningResultV1Set) NullField(i int) {
	switch i {
	}
	panic("Not a nullable field index")
}

func (_ SigningResultV1Set) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ SigningResultV1Set) AppendArray() types.Field         { panic("Unsupported operation") }
func (_ SigningResultV1Set) HintSize(int)                     { panic("Unsupported operation") }
func (_ SigningResultV1Set) Finalize()                        {}

func (_ SigningResultV1Set) AvroCRC64Fingerprint() []byte {
	return []byte(SigningResultV1SetAvroCRC64Fingerprint)
}

func (r SigningResultV1Set) MarshalJSON() ([]byte, error) {
	var err error
	output := make(map[string]json.RawMessage)
	output["request_id"], err = json.Marshal(r.Request_id)
	if err != nil {
		return nil, err
	}
	output["data"], err = json.Marshal(r.Data)
	if err != nil {
		return nil, err
	}
	return json.Marshal(output)
}

func (r *SigningResultV1Set) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}

	var val json.RawMessage
	val = func() json.RawMessage {
		if v, ok := fields["request_id"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Request_id); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for request_id")
	}
	val = func() json.RawMessage {
		if v, ok := fields["data"]; ok {
			return v
		}
		return nil
	}()

	if val != nil {
		if err := json.Unmarshal([]byte(val), &r.Data); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("no value specified for data")
	}
	return nil
}