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
		t.Errorf("%v is exemept, but it shouldn't be", other)
	}
}
