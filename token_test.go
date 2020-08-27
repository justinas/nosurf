package nosurf

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestChecksForPRNG(t *testing.T) {
	// Monkeypatch crypto/rand with an always-failing reader
	oldReader := rand.Reader
	rand.Reader = failReader{}
	// Restore it later for other tests
	defer func() {
		rand.Reader = oldReader
	}()

	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("Expected checkForPRNG() to panic")
		}
	}()

	checkForPRNG()
}

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

func TestVerifyTokenChecksLengthCorrectly(t *testing.T) {
	for i := 0; i < 64; i++ {
		slice := make([]byte, i)
		result := verifyToken(slice, slice)
		if result {
			t.Errorf("VerifyToken should've returned false with slices of length %d", i)
		}
	}

	slice := make([]byte, 64)
	result := verifyToken(slice[:32], slice)
	if !result {
		t.Errorf("VerifyToken should've returned true on a zeroed slice of length 64")
	}
}

func TestVerifiesMaskedTokenCorrectly(t *testing.T) {
	realToken := []byte("qwertyuiopasdfghjklzxcvbnm123456")
	sentToken := []byte("qwertyuiopasdfghjklzxcvbnm123456" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	if !verifyToken(realToken, sentToken) {
		t.Errorf("VerifyToken returned a false negative")
	}

	realToken[0] = 'x'

	if verifyToken(realToken, sentToken) {
		t.Errorf("VerifyToken returned a false positive")
	}
}

func TestVerifyTokenBase64Invalid(t *testing.T) {
	for _, pairs := range [][]string{
		{"foo", "bar"},
		{"foo", ""},
		{"", "bar"},
		{"", ""},
	} {
		if VerifyToken(pairs[0], pairs[1]) {
			t.Errorf("VerifyToken returned a false positive for: %v", pairs)
		}
	}
}

func TestVerifyTokenUnMasked(t *testing.T) {
	for i, tc := range []struct {
		real  string
		send  string
		valid bool
	}{
		{
			real:  "qwertyuiopasdfghjklzxcvbnm123456",
			send:  "qwertyuiopasdfghjklzxcvbnm123456",
			valid: true,
		},
		{
			real: "qwertyuiopasdfghjklzxcvbnm123456",
			send: "qwertyuiopasdfghjklzxcvbnm123456" +
				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			valid: true,
		},
		{
			real: "qwertyuiopasdfghjklzxcvbnm123456" +
				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			send: "qwertyuiopasdfghjklzxcvbnm123456" +
				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			valid: true,
		},
		{
			real: "qwertyuiopasdfghjklzxcvbnm123456" +
				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			send:  "qwertyuiopasdfghjklzxcvbnm123456",
			valid: true,
		},
	} {
		if VerifyToken(
			base64.StdEncoding.EncodeToString([]byte(tc.real)),
			base64.StdEncoding.EncodeToString([]byte(tc.send)),
		) != tc.valid {
			t.Errorf("Verify token returned wrong result for case %d: %+v", i, tc)
		}
	}
}
