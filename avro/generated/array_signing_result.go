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
	"io"

	"github.com/actgardner/gogen-avro/v9/vm"
	"github.com/actgardner/gogen-avro/v9/vm/types"
)

func writeArraySigningResult(r []SigningResult, w io.Writer) error {
	err := vm.WriteLong(int64(len(r)), w)
	if err != nil || len(r) == 0 {
		return err
	}
	for _, e := range r {
		err = writeSigningResult(e, w)
		if err != nil {
			return err
		}
	}
	return vm.WriteLong(0, w)
}

type ArraySigningResultWrapper struct {
	Target *[]SigningResult
}

func (_ *ArraySigningResultWrapper) SetBoolean(v bool)                { panic("Unsupported operation") }
func (_ *ArraySigningResultWrapper) SetInt(v int32)                   { panic("Unsupported operation") }
func (_ *ArraySigningResultWrapper) SetLong(v int64)                  { panic("Unsupported operation") }
func (_ *ArraySigningResultWrapper) SetFloat(v float32)               { panic("Unsupported operation") }
func (_ *ArraySigningResultWrapper) SetDouble(v float64)              { panic("Unsupported operation") }
func (_ *ArraySigningResultWrapper) SetBytes(v []byte)                { panic("Unsupported operation") }
func (_ *ArraySigningResultWrapper) SetString(v string)               { panic("Unsupported operation") }
func (_ *ArraySigningResultWrapper) SetUnionElem(v int64)             { panic("Unsupported operation") }
func (_ *ArraySigningResultWrapper) Get(i int) types.Field            { panic("Unsupported operation") }
func (_ *ArraySigningResultWrapper) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ *ArraySigningResultWrapper) Finalize()                        {}
func (_ *ArraySigningResultWrapper) SetDefault(i int)                 { panic("Unsupported operation") }
func (r *ArraySigningResultWrapper) NullField(i int) {
	panic("Unsupported operation")
}

func (r *ArraySigningResultWrapper) AppendArray() types.Field {
	var v SigningResult
	v = NewSigningResult()

	*r.Target = append(*r.Target, v)
	return &types.Record{Target: &(*r.Target)[len(*r.Target)-1]}
}