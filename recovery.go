package slim

import (
	"fmt"
	"runtime"
)

// RecoveryConfig defines the config for Recovery middleware.
type RecoveryConfig struct {
	// Size of the stack to be printed.
	// Optional. Default value 4KB.
	StackSize int
	// DisableStackAll disables formatting stack traces of all other goroutines
	// into buffer after the trace for the current goroutine.
	// Optional. Default value is false.
	DisableStackAll bool
	// DisablePrintStack disables printing stack trace.
	// Optional. Default value as false.
	DisablePrintStack bool
}

// DefaultRecoveryConfig is the default Recovery middleware config.
var DefaultRecoveryConfig = RecoveryConfig{
	StackSize:         4 << 10, // 4 KB
	DisableStackAll:   false,
	DisablePrintStack: false,
}

// Recovery returns a middleware which recovers from panics anywhere in the chain
// and handles the control to the centralized ErrorHandler.
func Recovery() MiddlewareFunc {
	return RecoveryWithConfig(DefaultRecoveryConfig)
}

// RecoveryWithConfig returns Recovery middleware with config or panics on invalid configuration.
func RecoveryWithConfig(config RecoveryConfig) MiddlewareFunc {
	return config.ToMiddleware()
}

// ToMiddleware converts RecoveryConfig to middleware or returns an error for invalid configuration
func (config RecoveryConfig) ToMiddleware() MiddlewareFunc {
	if config.StackSize == 0 {
		config.StackSize = DefaultRecoveryConfig.StackSize
	}
	return func(c Context, next HandlerFunc) (err error) {
		defer func() {
			if r := recover(); r != nil {
				tmpErr, ok := r.(error)
				if !ok {
					tmpErr = fmt.Errorf("%v", r)
				}
				if !config.DisablePrintStack {
					stack := make([]byte, config.StackSize)
					length := runtime.Stack(stack, !config.DisableStackAll)
					tmpErr = fmt.Errorf("[PANIC RECOVER] %w %s", tmpErr, stack[:length])
				}
				err = tmpErr
			}
		}()
		err = next(c)
		return
	}
}
