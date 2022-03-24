// Code generated by github.com/actgardner/gogen-avro/v10. DO NOT EDIT.
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

	"github.com/actgardner/gogen-avro/v10/vm"
	"github.com/actgardner/gogen-avro/v10/vm/types"
)

func writeArrayRedeemRequest(r []RedeemRequest, w io.Writer) error {
	err := vm.WriteLong(int64(len(r)), w)
	if err != nil || len(r) == 0 {
		return err
	}
	for _, e := range r {
		err = writeRedeemRequest(e, w)
		if err != nil {
			return err
		}
	}
	return vm.WriteLong(0, w)
}

type ArrayRedeemRequestWrapper struct {
	Target *[]RedeemRequest
}

func (_ ArrayRedeemRequestWrapper) SetBoolean(v bool)                { panic("Unsupported operation") }
func (_ ArrayRedeemRequestWrapper) SetInt(v int32)                   { panic("Unsupported operation") }
func (_ ArrayRedeemRequestWrapper) SetLong(v int64)                  { panic("Unsupported operation") }
func (_ ArrayRedeemRequestWrapper) SetFloat(v float32)               { panic("Unsupported operation") }
func (_ ArrayRedeemRequestWrapper) SetDouble(v float64)              { panic("Unsupported operation") }
func (_ ArrayRedeemRequestWrapper) SetBytes(v []byte)                { panic("Unsupported operation") }
func (_ ArrayRedeemRequestWrapper) SetString(v string)               { panic("Unsupported operation") }
func (_ ArrayRedeemRequestWrapper) SetUnionElem(v int64)             { panic("Unsupported operation") }
func (_ ArrayRedeemRequestWrapper) Get(i int) types.Field            { panic("Unsupported operation") }
func (_ ArrayRedeemRequestWrapper) AppendMap(key string) types.Field { panic("Unsupported operation") }
func (_ ArrayRedeemRequestWrapper) Finalize()                        {}
func (_ ArrayRedeemRequestWrapper) SetDefault(i int)                 { panic("Unsupported operation") }
func (r ArrayRedeemRequestWrapper) HintSize(s int) {
	if len(*r.Target) == 0 {
		*r.Target = make([]RedeemRequest, 0, s)
	}
}
func (r ArrayRedeemRequestWrapper) NullField(i int) {
	panic("Unsupported operation")
}

func (r ArrayRedeemRequestWrapper) AppendArray() types.Field {
	var v RedeemRequest
	v = NewRedeemRequest()

	*r.Target = append(*r.Target, v)
	return &types.Record{Target: &(*r.Target)[len(*r.Target)-1]}
}
