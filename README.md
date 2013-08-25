# nosurf

`nosurf` is an HTTP package for Go
that helps you prevent Cross-Site Request Forgery attacks.
It acts like a middleware and therefore 
is compatible with basically any Go HTTP application.

### Why?
Even though CSRF is a prominent vulnerability,
Go's web-related package infrastructure mostly consists of
micro-frameworks that neither do implement CSRF checks,
nor should they.

`nosurf` solves this problem by proving a `CSRFHandler`
that wraps your `http.Handler` and checks for CSRF attacks
on every non-safe (non-GET/HEAD/OPTIONS/TRACE) method.


### Features

* Supports any `http.Handler` (frameworks, your own handlers, etc.)
and acts like one itself.
* Allows exempting specific endpoints from CSRF checks by
an exact URL, a glob, or a regular expression.
* Allows specifying your own failure handler. 
Want to present the hacker with an ASCII middle finger
instead of the plain old `HTTP 400`? No problem.
