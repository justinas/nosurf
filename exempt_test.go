package nosurf

import (
	"regexp"
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
		t.Errorf("%v is exempt, but it shouldn't be", other)
	}
}

func TestExemptGlob(t *testing.T) {
	hand := New(nil)
	glob := "/[m-n]ail"

	hand.ExemptGlob(glob)

	test := "/mail"
	if !hand.IsExempt(test) {
		t.Errorf("%v should be exempt, but it isn't.", test)
	}

	test = "/nail"
	if !hand.IsExempt(test) {
		t.Errorf("%v should be exempt, but it isn't.", test)
	}

	test = "/snail"
	if hand.IsExempt(test) {
		t.Errorf("%v should not be exempt, but it is.", test)
	}

	test = "/mail/outbox"
	if hand.IsExempt(test) {
		t.Errorf("%v should not be exempt, but it is.", test)
	}
}

func TestExemptGlobs(t *testing.T) {
	slice := []string{"/", "/accounts/*", "/post/?*"}
	matching := []string{"/", "/accounts/", "/accounts/johndoe", "/post/1", "/post/123"}

	nonMatching := []string{"", "/accounts",
		// glob's * and ? don't match a forward slash
		"/accounts/johndoe/posts",
		"/post/",
	}

	hand := New(nil)
	hand.ExemptGlobs(slice...)

	for _, v := range matching {
		if !hand.IsExempt(v) {
			t.Errorf("%v should be exempt, but it isn't.", v)
		}
	}

	for _, v := range nonMatching {
		if hand.IsExempt(v) {
			t.Errorf("%v shouldn't be exempt, but it is", v)
		}
	}
}

// This only tests that ExemptRegexp handles the argument correctly
// The matching itself is tested by TestExemptRegexpMatching
func TestExemptRegexpCall(t *testing.T) {
	pattern := "^/[rd]ope$"

	// case 1: a string
	hand := New(nil)
	hand.ExemptRegexp(pattern)

	// String() returns the original pattern
	got := hand.exemptRegexps[0].String()

	if pattern != got {
		t.Errorf("The compiled pattern has changed: expected %v, got %v",
			pattern, got)
	}

	// case 2: a compiled *Regexp
	hand = New(nil)
	re := regexp.MustCompile(pattern)
	hand.ExemptRegexp(re)

	got_re := hand.exemptRegexps[0]

	if re != got_re {
		t.Errorf("The compiled pattern is not what we gave: expected %v, got %v",
			re, got_re)
	}

}

func TestExemptRegexpInvalidType(t *testing.T) {
	arg := 123

	defer func() {
		r := recover()
		if r == nil {
			t.Error("The function didn't panic on an invalid argument type")
		}
	}()

	hand := New(nil)
	hand.ExemptRegexp(arg)
}

func TestExemptRegexpInvalidPattern(t *testing.T) {
	// an unclosed group
	pattern := "a(b"

	defer func() {
		r := recover()
		if r == nil {
			t.Error("The function didn't panic on an invalid regular expression")
		}
	}()

	hand := New(nil)
	hand.ExemptRegexp(pattern)
}

// The same as TestExemptRegexCall, but for the variadic function
func TestExemptRegexpsCall(t *testing.T) {
	// case 1: a slice of strings
	hand := New(nil)
	slice1 := []interface{}{"^/$", "^/accounts$"}
	hand.ExemptRegexps(slice1...)

	for i := range slice1 {
		pat := hand.exemptRegexps[i].String()
		got := slice1[i]
		if pat != got {
			t.Errorf("The compiled pattern has changed: expected %v, got %v", pat, got)
		}
	}

	// case 2: a mixed slice
	hand = New(nil)
	slice2 := []interface{}{"^/$", regexp.MustCompile("^/accounts$")}
	hand.ExemptRegexps(slice2...)

	pat := slice2[0].(string)
	got := hand.exemptRegexps[0].String()
	if pat != got {
		t.Errorf("The compiled pattern has changed: expected %v, got %v", pat, got)
	}

	pat = slice2[1].(*regexp.Regexp).String()
	got = hand.exemptRegexps[1].String()
	if pat != got {
		t.Errorf("The compiled pattern has changed: expected %v, got %v", pat, got)
	}
}

func TestExemptRegexpMatching(t *testing.T) {
	hand := New(nil)
	re := `^/[mn]ail$`
	hand.ExemptRegexp(re)

	// valid
	test := "/mail"
	if !hand.IsExempt(test) {
		t.Errorf("%v should be exempt, but it isn't.", test)
	}

	test = "/nail"
	if !hand.IsExempt(test) {
		t.Errorf("%v should be exempt, but it isn't.", test)
	}

	test = "/mail/outbox"
	if hand.IsExempt(test) {
		t.Errorf("%v shouldn't be exempt, but it is.", test)
	}

	test = "/snail"
	if hand.IsExempt(test) {
		t.Errorf("%v shouldn't be exempt, but it is.", test)
	}
}
