package logger

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	DEBUG = 0
	INFO  = 1
	WARN  = 2
	ERROR = 3
)

var logLevel int

func init() {
	env := strings.ToUpper(os.Getenv("LOG_LEVEL"))
	switch env {
	case "DEBUG":
		logLevel = DEBUG
	case "WARN":
		logLevel = WARN
	case "ERROR":
		logLevel = ERROR
	default:
		logLevel = INFO
	}
}

func log(msg string, level int) {
	if level < logLevel {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	prefix := "INFO"
	switch level {
	case DEBUG:
		prefix = "DEBUG"
	case WARN:
		prefix = "WARN"
	case ERROR:
		prefix = "ERROR"
	}
	fmt.Printf("[%s] [%s] %s\n", ts, prefix, msg)
}

func Debug(msg string) { log(msg, DEBUG) }
func Info(msg string)  { log(msg, INFO) }
func Warn(msg string)  { log(msg, WARN) }
func Error(msg string) { log(msg, ERROR) }

func Debugf(format string, a ...any) { log(fmt.Sprintf(format, a...), DEBUG) }
func Infof(format string, a ...any)  { log(fmt.Sprintf(format, a...), INFO) }
func Warnf(format string, a ...any)  { log(fmt.Sprintf(format, a...), WARN) }
func Errorf(format string, a ...any) { log(fmt.Sprintf(format, a...), ERROR) }

func Mask(s string, show int) string {
	if s == "" || len(s) <= show {
		return "****"
	}
	return s[:show] + "****"
}

func MaskPhone(phone string) string {
	if phone == "" || len(phone) < 7 {
		return "****"
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}
