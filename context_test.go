package nosurf

import (
	"errors"
	"testing"
)

func TestSetsReasonCorrectly(t *testing.T) {
	req := dummyGet()

	// set token first, as it's required for setReason
	setToken(req, "abcdef")

	err := errors.New("universe imploded")
	setReason(req, err)

	got := contextMap[req].reason

	if got != err {
		t.Errorf("Reason set incorrectly: expected %v, got %v", err, got)
	}
}

func TestSettingReasonFailsWithoutContext(t *testing.T) {
	req := dummyGet()
	err := errors.New("universe imploded")

	defer func() {
		r := recover()
		if r == nil {
			t.Error("setReason() didn't panic on no context")
		}
	}()

	setReason(req, err)
}

func TestSetsTokenCorrectly(t *testing.T) {
	req := dummyGet()
	token := "abcdef"
	setToken(req, token)

	got := contextMap[req].token

	if got != token {
		t.Errorf("Token set incorrectly: expected %v, got %v", token, got)
	}
}

func TestGetsTokenCorrectly(t *testing.T) {
	req := dummyGet()
	token := Token(req)

	if token != "" {
		t.Errorf("Token hasn't been set yet, but it's not an empty string, it's %v", token)
	}

	intended := "abcdef"
	setToken(req, intended)

	token = Token(req)
	if token != "abcdef" {
		t.Errorf("Token has been set to %v, but it's %v", intended, token)
	}
}

func TestGetsReasonCorrectly(t *testing.T) {
	req := dummyGet()

	reason := Reason(req)
	if reason != nil {
		t.Errorf("Reason hasn't been set yet, but it's not nil, it's %v", reason)
	}

	// again, needed for setReason() to work
	setToken(req, "dummy")

	intended := errors.New("universe imploded")
	setReason(req, intended)

	reason = Reason(req)
	if reason != intended {
		t.Errorf("Reason has been set to %v, but it's %v", intended, reason)
	}
}
