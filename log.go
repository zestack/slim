package slim

// Logger defines the logging interface.
type Logger interface {
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
