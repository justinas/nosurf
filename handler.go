// Package nosurf implements an HTTP handler that
// mitigates Cross-Site Request Forgery Attacks.
package nosurf

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
)

const (
	// the name of CSRF cookie
	CookieName = "csrf_token"
	// the name of the form field
	FormFieldName = "csrf_token"
	// the name of CSRF header
	HeaderName = "X-CSRF-Token"
	// the HTTP status code for the default failure handler
	FailureCode = 400

	// Max-Age in seconds for the default base cookie. 365 days.
	MaxAge = 365 * 24 * 60 * 60
)

var safeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}

// reasons for CSRF check failures
var (
	ErrNoReferer  = errors.New("A secure request contained no Referer or its value was malformed")
	ErrBadReferer = errors.New("A secure request's Referer comes from a different Origin" +
		" from the request's URL")
)

type CSRFHandler struct {
	// Handlers that CSRFHandler wraps.
	successHandler http.Handler
	failureHandler http.Handler

	// The base cookie that CSRF cookies will be built upon.
	// This should be a better solution of customizing the options
	// than a bunch of methods SetCookieExpiration(), etc.
	baseCookie http.Cookie

	// Slices of paths that are exempt from CSRF checks.
	// They can be specified by...
	// ...an exact path,
	exemptPaths []string
	// ...a regexp,
	exemptRegexps []*regexp.Regexp
	// ...or a glob (as used by path.Match()).
	exemptGlobs []string

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
	baseCookie.MaxAge = MaxAge

	csrf := &CSRFHandler{successHandler: handler,
		failureHandler: http.HandlerFunc(defaultFailureHandler),
		exemptPaths:    make([]string, 0),
		exemptGlobs:    make([]string, 0),
		exemptRegexps:  make([]*regexp.Regexp, 0),
		baseCookie:     baseCookie,
	}

	return csrf
}

func (h *CSRFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Prefer the header over form value
	sent_token := r.Header.Get(HeaderName)
	if sent_token == "" {
		sent_token = r.PostFormValue(FormFieldName)
	}

	token_cookie, err := r.Cookie(CookieName)
	real_token := ""
	if err == http.ErrNoCookie {
		real_token = h.RegenerateToken(w, r)
	} else {
		real_token = token_cookie.Value
	}

	// If the length of the real token isn't what it should be,
	// it has either been tampered with,
	// or we're migrating onto a new algorithm for generating tokens.
	// In any case of those, we should regenerate it.
	//
	// As a consequence, CSRF check will fail when comparing the tokens later on,
	// so we don't have to fail it just yet.
	if len(real_token) != tokenLength {
		real_token = h.RegenerateToken(w, r)
	}

	// clear the context after the request is served
	defer ctxClear(r)
	ctxSetToken(r, real_token)

	if sContains(safeMethods, r.Method) {
		// short-circuit with a success for safe methods
		h.handleSuccess(w, r)
		return
	}

	// if the request is secure, we enforce origin check
	// for referer to prevent MITM of http->https requests
	if r.URL.Scheme == "https" {
		referer, err := url.Parse(r.Header.Get("Referer"))

		// if we can't parse the referer or it's empty,
		// we assume it's not specified
		if err != nil || referer.String() == "" {
			ctxSetReason(r, ErrNoReferer)
			h.handleFailure(w, r)
			return
		}

		// if the referer doesn't share origin with the request URL,
		// we have another error for that
		if !sameOrigin(referer, r.URL) {
			ctxSetReason(r, ErrBadReferer)
			h.handleFailure(w, r)
			return
		}
	}

}

// handleSuccess simply calls the successHandler
// everything else, like setting a token in the context
// is taken care of by h.ServeHTTP()
func (h *CSRFHandler) handleSuccess(w http.ResponseWriter, r *http.Request) {
	// On a successful check, we might as well renew the cookie.
	token := Token(r)
	h.setTokenCookie(w, r, token)

	h.successHandler.ServeHTTP(w, r)
}

// Same applies here: h.ServeHTTP() sets the failure reason, the token,
// and only then calls handleFailure()
func (h *CSRFHandler) handleFailure(w http.ResponseWriter, r *http.Request) {
	h.failureHandler.ServeHTTP(w, r)
}

// Generates a new token, sets it on the given request and returns it
func (h *CSRFHandler) RegenerateToken(w http.ResponseWriter, r *http.Request) string {
	token := generateToken()
	h.setTokenCookie(w, r, token)

	return token
}

func (h *CSRFHandler) setTokenCookie(w http.ResponseWriter, r *http.Request, token string) {
	cookie := h.baseCookie
	cookie.Name = CookieName
	cookie.Value = token

	http.SetCookie(w, &cookie)

	ctxSetToken(r, token)
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
