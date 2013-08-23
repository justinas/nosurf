package nosurf

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestGeneratesAValidToken(t *testing.T) {
	// We can't test much with any certainity here,
	// since we generate hashes from random numbers.

	// Basically we check that the length of the
	// encoded / decoded token is what it should be

	token := generateToken()
	l := len(token)

	if l != tokenLength {
		t.Errorf("Bad token length: expected %d, got %d", l, tokenLength)
	}

	hash, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}

	l = len(hash)

	if l != sha256.Size {
		t.Errorf("Bad decoded token length: expected %d, got %d", l, sha256.Size)
	}
}
