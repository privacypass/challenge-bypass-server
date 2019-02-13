// Contains functions that are common to all test files for handling the
// different H2C settings.

package crypto

import (
	"testing"
)

// Runs the tests for each of the different H2C methods
func HandleTest(t *testing.T, h2cMethod string, testToRun func(t *testing.T, obj H2CObject)) {
	curveParams := &CurveParams{Curve: "p256", Hash: "sha256", Method: h2cMethod}
	h2cObj, err := curveParams.GetH2CObj()
	if err != nil {
		t.Fatal(err)
	}
	testToRun(t, h2cObj)
}
