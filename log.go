package slim

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Logger defines the logging interface.
type Logger interface {
	Output() io.Writer
	SetOutput(w io.Writer)
	Print(i ...any)
	Printf(format string, args ...any)
	Printj(j map[string]any)
	Debug(i ...any)
	Debugf(format string, args ...any)
	Debugj(j map[string]any)
	Info(i ...any)
	Infof(format string, args ...any)
	Infoj(j map[string]any)
	Warn(i ...any)
	Warnf(format string, args ...any)
	Warnj(j map[string]any)
	Error(i ...any)
	Errorf(format string, args ...any)
	Errorj(j map[string]any)
	Panic(i ...any)
	Panicf(format string, args ...any)
	Panicj(j map[string]any)
	Fatal(i ...any)
	Fatalf(format string, args ...any)
	Fatalj(j map[string]any)
}

func NewLogger() Logger {
	return &logger{
		output: os.Stderr,
		mutex:  sync.RWMutex{},
	}
}

type logger struct {
	output io.Writer
	mutex  sync.RWMutex
}

func (l *logger) Output() io.Writer {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.output
}

func (l *logger) SetOutput(w io.Writer) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.output = w
}

func (l *logger) Print(i ...any) {
	l.log("TRACE", "", i...)
}

func (l *logger) Printf(format string, args ...any) {
	l.log("TRACE", format, args...)
}

func (l *logger) Printj(j map[string]any) {
	l.log("TRACE", "json", j)
}

func (l *logger) Debug(i ...any) {
	l.log("DEBUG", "", i...)
}

func (l *logger) Debugf(format string, args ...any) {
	l.log("DEBUG", format, args...)
}

func (l *logger) Debugj(j map[string]any) {
	l.log("DEBUG", "json", j)
}

func (l *logger) Info(i ...any) {
	l.log("INFO", "", i...)
}

func (l *logger) Infof(format string, args ...any) {
	l.log("INFO", format, args...)
}

func (l *logger) Infoj(j map[string]any) {
	l.log("INFO", "json", j)
}

func (l *logger) Warn(i ...any) {
	l.log("WARN", "", i...)
}

func (l *logger) Warnf(format string, args ...any) {
	l.log("WARN", format, args...)
}

func (l *logger) Warnj(j map[string]any) {
	l.log("WARN", "json", j)
}

func (l *logger) Error(i ...any) {
	l.log("ERROR", "", i...)
}

func (l *logger) Errorf(format string, args ...any) {
	l.log("ERROR", format, args...)
}

func (l *logger) Errorj(j map[string]any) {
	l.log("ERROR", "json", j)
}

func (l *logger) Panic(i ...any) {
	l.log("PANIC", "", i...)
	panic(fmt.Sprint(i...))
}

func (l *logger) Panicf(format string, args ...any) {
	l.log("PANIC", format, args...)
	panic(fmt.Sprintf(format, args...))
}

func (l *logger) Panicj(j map[string]any) {
	l.log("PANIC", "json", j)
	panic(j)
}

func (l *logger) Fatal(i ...any) {
	l.log("FATAL", "", i...)
	os.Exit(1)
}

func (l *logger) Fatalf(format string, args ...any) {
	l.log("FATAL", format, args...)
	os.Exit(1)
}

func (l *logger) Fatalj(j map[string]any) {
	l.log("FATAL", "json", j)
	os.Exit(1)
}

func (l *logger) log(level string, format string, args ...any) {
	var message string
	if format == "" {
		message = fmt.Sprint(args...)
	} else if format == "json" {
		b, err := json.Marshal(args[0])
		if err != nil {
			panic(err)
		}
		message = string(b)
	} else {
		message = fmt.Sprintf(format, args...)
	}
	fmt.Fprintf(
		l.Output(),
		"%s | %-5s | %s\n",
		time.Now().Format("2006-01-02 15:04:05.000"),
		level,
		strings.TrimSpace(message),
	)
}

type LoggingConfig struct {
	Colorful bool
}

func Logging() MiddlewareFunc {
	return (LoggingConfig{
		Colorful: runtime.GOOS != "windows",
	}).ToMiddleware()
}

func (l LoggingConfig) ToMiddleware() MiddlewareFunc {
	return func(c Context, next HandlerFunc) (err error) {
		start := time.Now()
		c.Logger().Infof("Started %s %s for %s", c.Request().Method, c.RequestURI(), c.RealIP())
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
		if l.Colorful {
			if status >= 500 {
				content = fmt.Sprintf("\033[1;36m%s\033[0m", content)
			} else if status >= 400 {
				if status == 404 {
					content = fmt.Sprintf("\033[1;31m%s\033[0m", content)
				} else {
					content = fmt.Sprintf("\033[4;31m%s\033[0m", content)
				}
			} else if status >= 300 {
				if status == 304 {
					content = fmt.Sprintf("\033[1;33m%s\033[0m", content)
				} else {
					content = fmt.Sprintf("\033[1;37m%s\033[0m", content)
				}
			} else if status >= 200 {
				content = fmt.Sprintf("\033[1;32m%s\033[0m", content)
			}
		}
		c.Logger().Info(content)
		return
	}
}
