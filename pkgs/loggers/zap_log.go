package loggers

import (
	"os"
	"user_service/pkgs/settings"

	"github.com/natefinch/lumberjack"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type LoggerZap struct {
	*zap.Logger
}

func removeOldLogIfExists(path string) {
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(path)
	}
}

func NewLogger(config settings.LoggerSetting) *LoggerZap {
	removeOldLogIfExists(config.FileLogName)

	logLevel := config.LogLevel
	// debug -> info -> warn -> error -> fatal -> panic
	var level zapcore.Level

	switch logLevel {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	encoder := getEncoderLog()
	hook := lumberjack.Logger{
		Filename:   config.FileLogName,
		MaxSize:    config.MaxSize,
		MaxBackups: config.MaxBackups,
		MaxAge:     config.MaxAge,
		Compress:   config.Compress,
	}
	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(&hook),
		level,
	)

	return &LoggerZap{zap.New(core, zap.AddCaller())}
}

// format logs a message
func getEncoderLog() zapcore.Encoder {
	encodeConfig := zap.NewProductionEncoderConfig()
	// 1716714967.877995 -> 2024-05-26T16:16:07.877+0700
	encodeConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	// ts -> Time
	encodeConfig.TimeKey = "time"
	// from info INFO
	encodeConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	// "caller": "cli/main.log.go:24"
	encodeConfig.EncodeCaller = zapcore.ShortCallerEncoder // zao.Ne

	return zapcore.NewJSONEncoder(encodeConfig)
}
