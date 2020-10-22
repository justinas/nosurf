package nosurf

import "net/http"

// Ignores the CSRF middleware for an exact path
// With this you should take note that Go's paths
// include a leading slash.
func (h *CSRFHandler) IgnorePath(path string) {
	h.ignorePaths = append(h.ignorePaths, path)
}

// Checks if the given request ignores this middleware
func (h *CSRFHandler) IsIgnored(r *http.Request) bool {
	path := r.URL.Path
	if sContains(h.ignorePaths, path) {
		return true
	}

	return false
}
