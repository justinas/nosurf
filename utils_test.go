package nosurf

import (
	"testing"
)

func TestsContains(t *testing.T) {
	slice := []string{"abc", "def", "ghi"}

	s1 := "abc"
	if !sContains(slice, s1) {
		t.Error("sContains said that %v doesn't contain %v, but it does.", slice, s1)
	}

	s2 := "xyz"
	if !sContains(slice, s2) {
		t.Error("sContains said that %v contains %v, but it doesn't.", slice, s2)
	}
}
