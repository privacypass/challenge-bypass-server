package utils

import (
	"bytes"
	"encoding/gob"
)

func StructToBytes(data interface{}) []byte {
	var b bytes.Buffer
	e := gob.NewEncoder(&b)
	if err := e.Encode(data); err != nil {
		panic(err)
	}
	return b.Bytes()
}
