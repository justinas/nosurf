package nosurf

import (
	_ "path"
	_ "regexp"
)

// Checks if the given path is exempt from CSRF checks
func (h *CSRFHandler) IsExempt(path string) bool {
	// Check the exact urls first (the most specific rule)
	if sContains(h.exemptPaths, path) {
		return true
	}

	return false
}

// Exempts an exact path from CSRF checks
// With this (and other Exempt* methods)
// you should take note that Go's paths
// include a trailing slash.
func (h *CSRFHandler) ExemptPath(path string) {
	h.exemptPaths = append(h.exemptPaths, path)
}

// A convienience function to exempt several paths at once
func (h *CSRFHandler) ExemptPaths(paths ...string) {
	for _, v := range paths {
		h.ExemptPath(v)
	}
}
