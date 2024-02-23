package dig

import (
	"fmt"
	"os"
)

type Logger struct {
	Verbose bool
}

func (l *Logger) logV(format string, a ...any) {
	if l.Verbose {
		fmt.Fprintf(os.Stdout, format, a...)
	}
}

func (l *Logger) log(format string, a ...any) {
	fmt.Fprintf(os.Stdout, format, a...)
}
