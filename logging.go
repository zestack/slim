package slim

import (
	stdctx "context"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/xid"
	"zestack.dev/color"
	"zestack.dev/log"
)

type LoggingConfig struct {
	// DisableRequestID 是否开启 RequestID
	DisableRequestID bool
	// RequestIDGenerator 请求 ID 生成器
	RequestIDGenerator func(c Context) string
	// ForkedPrefixes 自定义的关联前缀的日志实例到请求上下文中，比如：
	//
	//   LoggingConfig{
	//     DisableRequestID: map[string]string{
	//       "db:logger":    "db",    // 将数据库操作与请求关联
	//       "redis:logger": "redis", // 将 redis 操作与请求关联
	//       //...其它关联
	//     }
	//   }
	ForkedPrefixes map[string]string
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
		l.Printf("Started %s %s for %s", c.Request().Method, c.RequestURI(), c.RealIP())
		ctx := stdctx.WithValue(c.Context(), "logger", l)
		if len(config.ForkedPrefixes) > 0 {
			for key, prefix := range config.ForkedPrefixes {
				ctx = stdctx.WithValue(ctx, key, l.WithPrefix(prefix))
			}
		}
		c.SetRequest(c.Request().WithContext(ctx))
		c.SetLogger(l)
		if err = next(c); err != nil {
			c.Logger().Error(err)
		}
		stop := time.Now()
		status := c.Response().Status()
		content := fmt.Sprintf(
			"Completed %s %s %v %s in %s",
			c.Request().Method,
			c.RequestURI(),
			status,
			http.StatusText(c.Response().Status()),
			stop.Sub(start).String(),
		)
		if status >= 500 {
			content = color.Cyan(content)
		} else if status >= 400 {
			if status == 404 {
				content = color.Yellow(content)
			} else {
				content = color.Red(content)
			}
		} else if status >= 300 {
			if status == 304 {
				content = color.Yellow(content)
			} else {
				content = color.White(content)
			}
		}
		l.Print(content)
		return
	}
}
