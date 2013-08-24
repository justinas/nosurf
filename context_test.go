package nosurf

import (
	"errors"
	"testing"
)

func TestSetsReasonCorrectly(t *testing.T) {
	req := dummyGet()

	// set token first, as it's required for ctxSetReason
	ctxSetToken(req, "abcdef")

	err := errors.New("universe imploded")
	ctxSetReason(req, err)

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
			t.Error("ctxSetReason() didn't panic on no context")
		}
	}()

	ctxSetReason(req, err)
}

func TestSetsTokenCorrectly(t *testing.T) {
	req := dummyGet()
	token := "abcdef"
	ctxSetToken(req, token)

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
	ctxSetToken(req, intended)

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

	// again, needed for ctxSetReason() to work
	ctxSetToken(req, "dummy")

	intended := errors.New("universe imploded")
	ctxSetReason(req, intended)

	reason = Reason(req)
	if reason != intended {
		t.Errorf("Reason has been set to %v, but it's %v", intended, reason)
	}
}

func TestClearsContextEntry(t *testing.T) {
	req := dummyGet()

	ctxSetToken(req, "dummy")
	ctxSetReason(req, errors.New("some error"))

	ctxClear(req)

	entry, found := contextMap[req]

	if found {
		t.Errorf("Context entry %v found for the request %v, even though"+
			" it should have been cleared.", entry, req)
	}
}
