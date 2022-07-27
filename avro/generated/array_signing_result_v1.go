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
	"io"

	"github.com/actgardner/gogen-avro/v10/vm"
	"github.com/actgardner/gogen-avro/v10/vm/types"
)

func writeArraySigningResultV1(r []SigningResultV1, w io.Writer) error {
	err := vm.WriteLong(int64(len(r)), w)
	if err != nil || len(r) == 0 {
		return err
	}
	for _, e := range r {
		err = writeSigningResultV1(e, w)
		if err != nil {
			return err
		}
	}
	return vm.WriteLong(0, w)
}

type ArraySigningResultV1Wrapper struct {
	Target *[]SigningResultV1
}

func (_ ArraySigningResultV1Wrapper) SetBoolean(v bool)     { panic("Unsupported operation") }
func (_ ArraySigningResultV1Wrapper) SetInt(v int32)        { panic("Unsupported operation") }
func (_ ArraySigningResultV1Wrapper) SetLong(v int64)       { panic("Unsupported operation") }
func (_ ArraySigningResultV1Wrapper) SetFloat(v float32)    { panic("Unsupported operation") }
func (_ ArraySigningResultV1Wrapper) SetDouble(v float64)   { panic("Unsupported operation") }
func (_ ArraySigningResultV1Wrapper) SetBytes(v []byte)     { panic("Unsupported operation") }
func (_ ArraySigningResultV1Wrapper) SetString(v string)    { panic("Unsupported operation") }
func (_ ArraySigningResultV1Wrapper) SetUnionElem(v int64)  { panic("Unsupported operation") }
func (_ ArraySigningResultV1Wrapper) Get(i int) types.Field { panic("Unsupported operation") }
func (_ ArraySigningResultV1Wrapper) AppendMap(key string) types.Field {
	panic("Unsupported operation")
}
func (_ ArraySigningResultV1Wrapper) Finalize()        {}
func (_ ArraySigningResultV1Wrapper) SetDefault(i int) { panic("Unsupported operation") }
func (r ArraySigningResultV1Wrapper) HintSize(s int) {
	if len(*r.Target) == 0 {
		*r.Target = make([]SigningResultV1, 0, s)
	}
}
func (r ArraySigningResultV1Wrapper) NullField(i int) {
	panic("Unsupported operation")
}

func (r ArraySigningResultV1Wrapper) AppendArray() types.Field {
	var v SigningResultV1
	v = NewSigningResultV1()

	*r.Target = append(*r.Target, v)
	return &types.Record{Target: &(*r.Target)[len(*r.Target)-1]}
}
