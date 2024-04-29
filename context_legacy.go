// +build !go1.7

package nosurf

import (
	"net/http"
	"sync"
)

// This file implements a context similar to one found
// in gorilla/context, but tailored specifically for our use case
// and not using gorilla's package just because.

type csrfContext struct {
	// The masked, base64 encoded token
	// That's suitable for use in form fields, etc.
	token string
	// reason for the failure of CSRF check
	reason error
	// wasSent is true if `Set-Cookie` was called
	// for the `name=csrf_token` already. This prevents
	// duplicate `Set-Cookie: csrf_token` headers.
	// For more information see:
	// https://github.com/justinas/nosurf/pull/61
	wasSent bool
}

var (
	contextMap = make(map[*http.Request]*csrfContext)
	cmMutex    = new(sync.RWMutex)
)

// Token() takes an HTTP request and returns
// the CSRF token for that request
// or an empty string if the token does not exist.
//
// Note that the token won't be available after
// CSRFHandler finishes
// (that is, in another handler that wraps it,
// or after the request has been served)
func Token(req *http.Request) string {
	cmMutex.RLock()
	defer cmMutex.RUnlock()

	ctx, ok := contextMap[req]

	if !ok {
		return ""
	}

	return ctx.token
}

// Reason() takes an HTTP request and returns
// the reason of failure of the CSRF check for that request
//
// Note that the same availability restrictions apply for Reason() as for Token().
func Reason(req *http.Request) error {
	cmMutex.RLock()
	defer cmMutex.RUnlock()

	ctx, ok := contextMap[req]

	if !ok {
		return nil
	}

	return ctx.reason
}

// Takes a raw token, masks it with a per-request key,
// encodes in base64 and makes it available to the wrapped handler
func ctxSetToken(req *http.Request, token []byte) *http.Request {
	cmMutex.Lock()
	defer cmMutex.Unlock()

	ctx, ok := contextMap[req]
	if !ok {
		ctx = new(csrfContext)
		contextMap[req] = ctx
	}

	ctx.token = b64encode(maskToken(token))

	return req
}

func ctxSetSent(req *http.Request) {
	cmMutex.Lock()
	defer cmMutex.Unlock()

	ctx, ok := contextMap[req]
	if !ok {
		ctx = new(csrfContext)
		contextMap[req] = ctx
	}

	ctx.wasSent = true
}

func ctxWasSent(req *http.Request) bool {
	cmMutex.RLock()
	defer cmMutex.RUnlock()

	ctx, ok := contextMap[req]

	if !ok {
		return false
	}

	return ctx.wasSent
}

func ctxSetReason(req *http.Request, reason error) *http.Request {
	cmMutex.Lock()
	defer cmMutex.Unlock()

	ctx, ok := contextMap[req]
	if !ok {
		panic("Reason should never be set when there's no token" +
			" (context) yet.")
	}

	ctx.reason = reason
	return req
}

func ctxClear(req *http.Request) {
	cmMutex.Lock()
	defer cmMutex.Unlock()

	delete(contextMap, req)
}
