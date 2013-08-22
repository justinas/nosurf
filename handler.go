// Package nosurf implements an HTTP handler that
// mitigates Cross-Site Request Forgery Attacks.
package nosurf

import (
	"net/http"
	"regexp"
)

const (
	CookieName  = "csrf_token"
	HeaderName  = "X-CSRF-Token"
	FailureCode = 400
)

type CSRFHandler struct {
	// Handlers that CSRFHandler wraps.
	successHandler http.Handler
	failureHandler http.Handler

	// Slices of URLs that are exempt from CSRF checks.
	// They can be specified by...
	// ...an exact URL
	exemptURLs []string
	// ...a glob (as used by path.Match())
	exemptGlobs []string
	// ...a regexp.
	exemptRegexps []*regexp.Regexp

	// All of those will be matched against Request.URL.Path,
	// So they should begin with a leading slash
}

func defaultFailureHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(FailureCode)
}

// Constructs a new `CSRFHandler` that calls
// the specified handler if the CSRF check succeeds.
func New(handler http.Handler) *CSRFHandler {
	csrf := &CSRFHandler{successHandler: handler,
		failureHandler: http.HandlerFunc(defaultFailureHandler),
		exemptURLs:     make([]string, 0),
		exemptGlobs:    make([]string, 0),
		exemptRegexps:  make([]*regexp.Regexp, 0),
	}

	return csrf
}

// Sets the handler to call in case the CSRF check
// fails. By default it's `defaultFailureHandler`.
func (h *CSRFHandler) SetFailureHandler(handler http.Handler) {
	h.failureHandler = handler
}
