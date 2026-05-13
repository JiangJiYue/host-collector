package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

var levelNames = map[LogLevel]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
	FATAL: "FATAL",
}

type Logger struct {
	mu      sync.Mutex
	level   LogLevel
	fileLog *log.Logger
	logFile *os.File
}

var globalLogger *Logger

// InitLogger 初始化全局日志系统
// logDir: 日志目录，传空字符串则只输出到控制台
// level: 最低日志级别
func InitLogger(logDir string, level LogLevel) {
	l := &Logger{level: level}

	if logDir != "" {
		os.MkdirAll(logDir, 0700)
		now := time.Now().Format("20060102-150405")
		logPath := filepath.Join(logDir, fmt.Sprintf("windows-host-collector-%s.log", now))
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			l.logFile = f
			l.fileLog = log.New(f, "", 0)
		}
	}

	globalLogger = l
}

func GetLogger() *Logger {
	if globalLogger == nil {
		InitLogger("", DEBUG)
	}
	return globalLogger
}

func (l *Logger) output(level LogLevel, component string, format string, v ...interface{}) {
	if level < l.level {
		return
	}

	msg := fmt.Sprintf(format, v...)
	now := time.Now().Format("2006-01-02 15:04:05.000")

	_, file, line, ok := runtime.Caller(2)
	caller := "?"
	if ok {
		caller = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}

	line_out := fmt.Sprintf("[%s] %s %s [%s] %s", levelNames[level], now, caller, component, msg)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.fileLog != nil {
		l.fileLog.Output(0, line_out)
	}

	// ERROR 和 FATAL 同时输出到 stderr
	if level >= ERROR {
		os.Stderr.WriteString(line_out + "\n")
	}
}

func (l *Logger) Debug(component string, format string, v ...interface{}) {
	l.output(DEBUG, component, format, v...)
}

func (l *Logger) Info(component string, format string, v ...interface{}) {
	l.output(INFO, component, format, v...)
}

func (l *Logger) Warn(component string, format string, v ...interface{}) {
	l.output(WARN, component, format, v...)
}

func (l *Logger) Error(component string, format string, v ...interface{}) {
	l.output(ERROR, component, format, v...)
}

func (l *Logger) Fatal(component string, format string, v ...interface{}) {
	l.output(FATAL, component, format, v...)
	os.Exit(1)
}

// ── 全局便捷函数 ──

func Debug(component string, format string, v ...interface{}) {
	GetLogger().Debug(component, format, v...)
}

func Info(component string, format string, v ...interface{}) {
	GetLogger().Info(component, format, v...)
}

func Warn(component string, format string, v ...interface{}) {
	GetLogger().Warn(component, format, v...)
}

func LogError(component string, format string, v ...interface{}) {
	GetLogger().Error(component, format, v...)
}

func Fatal(component string, format string, v ...interface{}) {
	GetLogger().Fatal(component, format, v...)
}
