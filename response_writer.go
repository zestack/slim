package slim

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

// ResponseWriter is a wrapper around http.ResponseWriter that provides extra information about
// the response. It is recommended that middleware handlers use this construct to wrap a ResponseWriter
// if the functionality calls for it.
type ResponseWriter interface {
	http.ResponseWriter
	http.Flusher
	http.Pusher
	// Status returns the status code of the response or 0 if the response has not been written.
	Status() int
	// Written returns whether the ResponseWriter has been written.
	Written() bool
	// Size returns the size of the response body.
	Size() int
}

// NewResponseWriter creates a ResponseWriter that wraps an `http.ResponseWriter`
func NewResponseWriter(method string, rw http.ResponseWriter) ResponseWriter {
	return &responseWriter{method, rw, 0, 0}
}

type responseWriter struct {
	method string
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	if rw.Written() {
		// TODO(hupeh): rw.slim.logger.Warn("response already committed")
		return
	}
	rw.ResponseWriter.WriteHeader(statusCode)
	rw.status = statusCode
}

func (rw *responseWriter) Write(b []byte) (size int, err error) {
	if !rw.Written() {
		// The status will be StatusOK if WriteHeader has not been called yet
		rw.WriteHeader(http.StatusOK)
	}
	if rw.method != "HEAD" {
		size, err = rw.ResponseWriter.Write(b)
		rw.size += size
	}
	return size, err
}

func (rw *responseWriter) Status() int {
	return rw.status
}

func (rw *responseWriter) Size() int {
	return rw.size
}

func (rw *responseWriter) Written() bool {
	return rw.status != 0
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("the ResponseWriter doesn't support the Hijacker interface")
	}
	return hijacker.Hijack()
}

func (rw *responseWriter) Flush() {
	flusher, ok := rw.ResponseWriter.(http.Flusher)
	if ok {
		flusher.Flush()
	}
}

func (rw *responseWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := rw.ResponseWriter.(http.Pusher)
	if !ok {
		return errors.New("the ResponseWriter doesn't support the Pusher interface")
	}
	return pusher.Push(target, opts)
}
