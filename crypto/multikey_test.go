package crypto

import (
	"testing"
)

const (
	testSignKeyFile = "testdata/test-sign-key.pem"
	testOldKeysFile = "testdata/test-old-keys.pem"
)

func TestParseSigningKeyFile(t *testing.T) {
	curves, keys, err := ParseKeyFile(testSignKeyFile, true)
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 || len(curves) != 1 {
		t.Fatalf("bad ParseKeyFile: curves %d, keys %d", len(curves), len(keys))
	}
}

func TestParseOldKeysFile(t *testing.T) {
	curves, keys, err := ParseKeyFile(testOldKeysFile, false)
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 2 || len(curves) != 2 {
		t.Fatalf("bad ParseKeyFile: curves %d, keys %d", len(curves), len(keys))
	}
}
