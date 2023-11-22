package logger

import (
	"github.com/TheZeroSlave/zapsentry"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func GetLogger(debug bool, sentryDSN string, env string) (*zap.Logger, error) {
	var err error
	var l *zap.Logger

	if debug {
		l, err = zap.NewDevelopment()
		if err != nil {
			return nil, err
		}
	} else {
		l, err = zap.NewProduction()
		if err != nil {
			return nil, err
		}
	}

	cfg := zapsentry.Configuration{
		Level: zapcore.ErrorLevel,
		Tags: map[string]string{
			"environment": env,
			"app":         "demoApp",
		},
	}
	core, err := zapsentry.NewCore(cfg, zapsentry.NewSentryClientFromDSN(sentryDSN))
	if err != nil {
		return nil, err
	}

	l = zapsentry.AttachCoreToLogger(core, l)
	defer func() {
		_ = l.Sync()
	}()

	return l, err
}
