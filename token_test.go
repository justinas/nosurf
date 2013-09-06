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

func TestVerifyTokenChecksLengthCorrectly(t *testing.T) {
	for i := 0; i < 64; i++ {
		if i == 32 {
			continue
		}
		slice := make([]byte, i)
		result := verifyToken(slice, slice)
		if result != false {
			t.Errorf("verifyToken should've returned false with slices of length %d", i)
		}
	}
	slice := make([]byte, 32)
	result := verifyToken(slice, slice)
	if result != true {
		t.Errorf("verifyToken should've returned true on a zeroed slice of length 32")
	}

	slice = make([]byte, 64)
	result = verifyToken(slice[:32], slice)
	if result != true {
		t.Errorf("verifyToken should've returned true on a zeroed slice of length 64")
	}
}

func TestVerifiesPlainTokenCorrectly(t *testing.T) {
	slice1 := []byte("qwertyuiopasdfghjklzxcvbnm123456")
	slice2 := []byte("qwertyuiopasdfghjklzxcvbnm123456")

	if !verifyToken(slice1, slice2) {
		t.Errorf("verifyToken returned a false negative")
	}

	slice1[0] = 'x'

	if verifyToken(slice1, slice2) {
		t.Errorf("verifyToken returned a false positive")
	}
}

func TestVerifiesEncryptedTokenCorrectly(t *testing.T) {
	realToken := []byte("qwertyuiopasdfghjklzxcvbnm123456")
	sentToken := []byte("qwertyuiopasdfghjklzxcvbnm123456" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	if !verifyToken(realToken, sentToken) {
		t.Errorf("verifyToken returned a false negative")
	}

	realToken[0] = 'x'

	if verifyToken(realToken, sentToken) {
		t.Errorf("verifyToken returned a false positive")
	}
}
