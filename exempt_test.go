package nosurf

import (
	"testing"
)

func TestExemptPath(t *testing.T) {
	// the handler doesn't matter here, let's use nil
	hand := New(nil)
	path := "/home"

	hand.ExemptPath(path)
	if !hand.IsExempt(path) {
		t.Errorf("%v is not exempt, but it should be", path)
	}

	other := "/faq"
	if hand.IsExempt(other) {
		t.Errorf("%v is exempt, but it shouldn't be", other)
	}
}

func TestExemptPaths(t *testing.T) {
	hand := New(nil)
	paths := []string{"/home", "/news", "/help"}
	hand.ExemptPaths(paths...)

	for _, v := range paths {
		if !hand.IsExempt(v) {
			t.Errorf("%v should be exempt, but it isn't", v)
		}
	}

	other := "/accounts"

	if hand.IsExempt(other) {
		t.Errorf("%v is exempt, but it shouldn't be")
	}
}
