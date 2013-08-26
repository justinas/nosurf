package nosurf

import (
	"encoding/base64"
	"testing"
)

func TestGeneratesAValidToken(t *testing.T) {
	// We can't test much with any certainity here,
	// since we generate tokens randomly

	// Basically we check that the length of the
	// encoded / decoded token is what it should be

	token := generateToken()
	l := len(token)

	if l != tokenLength {
		t.Errorf("Bad token length: expected %d, got %d", tokenLength, l)
	}

	hash, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}

	l = len(hash)
	if l != rawTokenLength {
		t.Errorf("Bad decoded token length: expected %d, got %d", rawTokenLength, l)
	}
}
