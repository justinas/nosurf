package nosurf

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
