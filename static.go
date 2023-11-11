package slim

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
)

type StaticConfig struct {
	// Root directory from where the static content is served.
	// Required.
	Root string
	// Index file for serving a directory.
	// Optional. Default value "index.html".
	Index string
	// Enable HTML5 mode by forwarding all not-found requests to root so that
	// SPA (single-page application) can handle the routing.
	// Optional. Default value is false.
	HTML5 bool
	// Filesystem provides access to the static content.
	// Optional. Default to http.Dir(config.Root)
	Filesystem http.FileSystem
}

// Static returns Static middleware to serve static content from the provided
// root directory.
func Static(root string) MiddlewareFunc {
	return StaticConfig{}.ToMiddleware()
}

func (config StaticConfig) ToMiddleware() MiddlewareFunc {
	if config.Root == "" {
		config.Root = "." // For security, we want to restrict to CWD.
	}
	if config.Index == "" {
		config.Index = "index.html"
	}
	if config.Filesystem == nil {
		config.Filesystem = http.Dir(config.Root)
		config.Root = "."
	}

	return func(c Context, next HandlerFunc) error {
		p, err := url.PathUnescape(c.Request().URL.Path)
		if err != nil {
			return err
		}

		name := path.Join(config.Root, path.Clean("/"+p)) // "/"+ for security

		file, err := config.Filesystem.Open(name)
		if err != nil {
			if !isIgnorableOpenFileError(err) {
				return err
			}

			// file with that path did not exist, so we continue down in a middleware/handler chain,
			// hoping that we end up in handler that is meant to handle this request
			if err = next(c); err == nil {
				return err
			}

			var he *HTTPError
			if !(errors.As(err, &he) && config.HTML5 && he.StatusCode == http.StatusNotFound) {
				return err
			}

			file, err = config.Filesystem.Open(path.Join(config.Root, config.Index))
			if err != nil {
				return err
			}
		}

		defer file.Close()

		info, err := file.Stat()
		if err != nil {
			return err
		}

		if info.IsDir() {
			index, err := config.Filesystem.Open(path.Join(name, config.Index))
			if err != nil {
				return next(c)
			}

			defer index.Close()

			info, err = index.Stat()
			if err != nil {
				return err
			}

			return serveFile(c, index, info)
		}

		return serveFile(c, file, info)
	}
}

func serveFile(c Context, file http.File, info os.FileInfo) error {
	http.ServeContent(c.Response(), c.Request(), info.Name(), info.ModTime(), file)
	return nil
}

// We ignore these errors as there could be handler that matches request path.
func isIgnorableOpenFileError(err error) bool {
	if os.IsNotExist(err) {
		return true
	}
	if runtime.GOOS == "windows" {
		errTxt := err.Error()
		return errTxt == "http: invalid or unsafe file path" || errTxt == "invalid path"
	}
	return false
}
