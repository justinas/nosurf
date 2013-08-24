// Package nosurf implements an HTTP handler that
// mitigates Cross-Site Request Forgery Attacks.
package nosurf

import (
	"net/http"
	"regexp"
)

const (
	// the name of CSRF cookie
	CookieName = "csrf_token"
	// the name of CSRF header
	HeaderName = "X-CSRF-Token"
	// the HTTP status code for the default failure handler
	FailureCode = 400

	// Max-Age for the default base cookie. 365 days.
	DefaultMaxAge = 365 * 24 * 60 * 60
)

type CSRFHandler struct {
	// Handlers that CSRFHandler wraps.
	successHandler http.Handler
	failureHandler http.Handler

	// The base cookie that CSRF cookies will be built upon.
	// This should be a better solution of customizing the options
	// than a bunch of methods SetCookieExpiration(), etc.
	baseCookie http.Cookie

	// Slices of URLs that are exempt from CSRF checks.
	// They can be specified by...
	// ...an exact URL
	exemptURLs []string
	// ...a glob (as used by path.Match())
	exemptGlobs []string
	// ...a regexp.
	exemptRegexps []*regexp.Regexp

	// All of those will be matched against Request.URL.Path,
	// So they should take the leading slash into account
}

func defaultFailureHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(FailureCode)
}

// Constructs a new CSRFHandler that calls
// the specified handler if the CSRF check succeeds.
func New(handler http.Handler) *CSRFHandler {
	baseCookie := http.Cookie{}
	baseCookie.MaxAge = DefaultMaxAge

	csrf := &CSRFHandler{successHandler: handler,
		failureHandler: http.HandlerFunc(defaultFailureHandler),
		exemptURLs:     make([]string, 0),
		exemptGlobs:    make([]string, 0),
		exemptRegexps:  make([]*regexp.Regexp, 0),
		baseCookie:     baseCookie,
	}

	return csrf
}

// Generates a new token, sets it on the given request and returns it
func (h *CSRFHandler) RegenerateToken(w http.ResponseWriter, r *http.Request) string {
	token := generateToken()

	cookie := h.baseCookie
	cookie.Name = CookieName
	cookie.Value = token

	http.SetCookie(w, &cookie)

	ctxSetToken(r, token)

	return token
}

// Sets the handler to call in case the CSRF check
// fails. By default it's defaultFailureHandler.
func (h *CSRFHandler) SetFailureHandler(handler http.Handler) {
	h.failureHandler = handler
}

// Sets the base cookie to use when building a CSRF token cookie
// This way you can specify the Domain, Path, HttpOnly, Secure, etc.
func (h *CSRFHandler) SetBaseCookie(cookie http.Cookie) {
	h.baseCookie = cookie
}
