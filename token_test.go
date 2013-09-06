package nosurf

import (
	"testing"
)

func TestGeneratesAValidToken(t *testing.T) {
	// We can't test much with any certainity here,
	// since we generate tokens randomly
	// Basically we check that the length of the
	// token is what it should be

	token := generateToken()
	l := len(token)

	if l != tokenLength {
		t.Errorf("Bad decoded token length: expected %d, got %d", tokenLength, l)
	}
}
