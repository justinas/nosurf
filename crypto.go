package nosurf

import (
	"crypto/rand"
	"io"
)

// Encrypts / decrypts the given data *in place*
// with the given key
// Slices must be of the same length, or oneTimePad will panic
func oneTimePad(data, key []byte) {
	n := len(data)
	if n != len(key) {
		panic("Lengths of slices are not equal")
	}

	for i := 0; i < n; i++ {
		data[i] ^= key[i]
	}
}

func encryptToken(data []byte) []byte {
	if len(data) != tokenLength {
		return nil
	}

	// tokenLength*2 == len(enckey + token)
	result := make([]byte, 2*tokenLength)
	// the first half of the result is the encryption key
	// the second half is the encrypted token
	key := result[:tokenLength]
	token := result[tokenLength:]
	copy(token, data)

	// generate the encryption key
	io.ReadFull(rand.Reader, key)

	oneTimePad(token, key)
	return result
}

func decryptToken(data []byte) []byte {
	if len(data) != tokenLength*2 {
		return nil
	}

	key := data[:tokenLength]
	token := data[tokenLength:]
	oneTimePad(token, key)

	return token
}
