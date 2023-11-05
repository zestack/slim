package slim

import (
	"errors"
	"fmt"
	"net/http"
)

// Errors
var (
	ErrUnsupportedMediaType        = NewHTTPError(http.StatusUnsupportedMediaType)
	ErrNotFound                    = NewHTTPError(http.StatusNotFound)
	ErrUnauthorized                = NewHTTPError(http.StatusUnauthorized)
	ErrForbidden                   = NewHTTPError(http.StatusForbidden)
	ErrMethodNotAllowed            = NewHTTPError(http.StatusMethodNotAllowed)
	ErrStatusRequestEntityTooLarge = NewHTTPError(http.StatusRequestEntityTooLarge)
	ErrTooManyRequests             = NewHTTPError(http.StatusTooManyRequests)
	ErrBadRequest                  = NewHTTPError(http.StatusBadRequest)
	ErrBadGateway                  = NewHTTPError(http.StatusBadGateway)
	ErrInternalServerError         = NewHTTPError(http.StatusInternalServerError)
	ErrRequestTimeout              = NewHTTPError(http.StatusRequestTimeout)
	ErrServiceUnavailable          = NewHTTPError(http.StatusServiceUnavailable)
	ErrValidatorNotRegistered      = errors.New("validator not registered")
	ErrRendererNotRegistered       = errors.New("renderer not registered")
	ErrInvalidRedirectCode         = errors.New("invalid redirect status code")
	ErrCookieNotFound              = errors.New("cookie not found")
	ErrInvalidCertOrKeyType        = errors.New("invalid cert or key type, must be string or []byte")
	ErrInvalidListenerNetwork      = errors.New("invalid listener network")
	ErrFilesystemNotRegistered     = errors.New("filesystem not registered")
)

// HTTPError represents an error that occurred while handling a request.
type HTTPError struct {
	StatusCode int   `json:"-"`
	Message    any   `json:"message"`
	Internal   error `json:"-"` // Stores the error returned by an external dependency
}

// NewHTTPError creates a new HTTPError instance.
func NewHTTPError(code int, message ...any) *HTTPError { // FIXME: this need cleanup - why vararg if [0] is only used?
	he := &HTTPError{code, http.StatusText(code), nil}
	if len(message) > 0 {
		he.Message = message[0]
	}
	return he
}

// NewHTTPErrorWithInternal creates a new HTTPError instance with an internal error set.
func NewHTTPErrorWithInternal(code int, internalError error, message ...any) *HTTPError {
	he := NewHTTPError(code, message...)
	he.Internal = internalError
	return he
}

// Error makes it compatible with `error` interface.
func (he *HTTPError) Error() string {
	if he.Internal == nil {
		return fmt.Sprintf("code=%d, message=%v", he.StatusCode, he.Message)
	}
	return fmt.Sprintf("statusCode=%d, message=%v, internal=%v", he.StatusCode, he.Message, he.Internal)
}

// WithInternal returns clone of HTTPError with err set to HTTPError.Internal field
func (he *HTTPError) WithInternal(err error) *HTTPError {
	return &HTTPError{
		StatusCode: he.StatusCode,
		Message:    he.Message,
		Internal:   err,
	}
}

// Unwrap satisfies the Go 1.13 error wrapper interface.
func (he *HTTPError) Unwrap() error {
	return he.Internal
}
