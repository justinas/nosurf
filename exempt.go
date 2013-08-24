package nosurf

import (
	"fmt"
	_ "path"
	"reflect"
	"regexp"
)

// Checks if the given path is exempt from CSRF checks
func (h *CSRFHandler) IsExempt(path string) bool {
	// Check the exact urls first (the most specific rule)
	if sContains(h.exemptPaths, path) {
		return true
	}

	// glob checking will go here

	// finally, the regexps
	for _, re := range h.exemptRegexps {
		if re.MatchString(path) {
			return true
		}
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

// Exempts a regular expression string or a compiled *regexp.Regexp
// and exempts URLs that match it from CSRF checks.
//
// If the given argument is neither of the accepted values,
// or the given string fails to compile, ExemptRegexp() panics.
func (h *CSRFHandler) ExemptRegexp(re interface{}) {
	var compiled *regexp.Regexp

	switch re.(type) {
	case string:
		compiled = regexp.MustCompile(re.(string))
	case *regexp.Regexp:
		compiled = re.(*regexp.Regexp)
	default:
		err := fmt.Sprintf("%v isn't a valid type for ExemptRegexp()", reflect.TypeOf(re))
		panic(err)
	}

	h.exemptRegexps = append(h.exemptRegexps, compiled)
}

// A variadic argument version of ExemptRegexp()
func (h *CSRFHandler) ExemptRegexps(res ...interface{}) {
	for _, v := range res {
		h.ExemptRegexp(v)
	}
}
