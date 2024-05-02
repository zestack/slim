package slim

import (
	stdctx "context"
	"net/http"
	"time"
	"zestack.dev/color"

	"github.com/rs/xid"
	"zestack.dev/log"
)

type LoggingConfig struct {
	// DisableRequestID 是否开启 RequestID
	DisableRequestID bool
	// RequestIDGenerator 请求 ID 生成器
	RequestIDGenerator func(c Context) string
}

func Logging() MiddlewareFunc {
	return LoggingWithConfig(LoggingConfig{})
}

func LoggingWithConfig(config LoggingConfig) MiddlewareFunc {
	return config.ToMiddleware()
}

func requestId(c Context) string {
	id := c.Header(HeaderXRequestID)
	if id == "" {
		id = xid.New().String()
		c.SetHeader(HeaderXRequestID, id)
	}
	return id
}

func (config LoggingConfig) ToMiddleware() MiddlewareFunc {
	if config.RequestIDGenerator == nil {
		config.RequestIDGenerator = requestId
	}
	return func(c Context, next HandlerFunc) (err error) {
		if !c.Slim().Debug {
			return next(c)
		}
		start := time.Now()
		l := c.Logger()
		if !config.DisableRequestID {
			l = l.With(log.String("id", config.RequestIDGenerator(c)))
		}
		l.Trace("Started %s %s for %s", c.Request().Method, c.RequestURI(), c.RealIP())
		ctx := stdctx.WithValue(c.Context(), "logger", l)
		c.SetRequest(c.Request().WithContext(ctx))
		c.SetLogger(l)
		if err = next(c); err != nil {
			c.Logger().Error(err)
		}
		stop := time.Now()
		status := c.Response().Status()
		var coloredStatus any
		if status >= 500 {
			coloredStatus = color.NewValue(status, color.FgCyan)
		} else if status >= 400 {
			if status == 404 {
				coloredStatus = color.NewValue(status, color.FgYellow)
			} else {
				coloredStatus = color.NewValue(status, color.FgRed)
			}
		} else if status >= 300 {
			if status == 304 {
				coloredStatus = color.NewValue(status, color.FgYellow)
			} else {
				coloredStatus = color.NewValue(status, color.FgWhite)
			}
		} else {
			coloredStatus = color.NewValue(status, color.FgGreen)
		}

		l.Trace(
			"Completed %s %s %v %s in %s",
			c.Request().Method,
			c.RequestURI(),
			coloredStatus,
			http.StatusText(c.Response().Status()),
			stop.Sub(start).String(),
		)
		return
	}
}
