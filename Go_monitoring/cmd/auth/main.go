package main

import (
	"context"
	"errors"
	"flag"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"log"
	"os"
	"os/signal"

	"github.com/anonimpopov/hw4/internal/app"
	"github.com/anonimpopov/hw4/internal/logger"
	otelprovider "github.com/anonimpopov/hw4/internal/otel"

	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

const (
	DSN         = "https://5797249e024b618265519d5736d33fbc@o4506248439791616.ingest.sentry.io/4506248444772352"
	TRACER_NAME = "demo_service"
)

func getConfigPath() string {
	var configPath string

	flag.StringVar(&configPath, "c", ".config/auth.yaml", "path to config file")
	flag.Parse()

	return configPath
}

func main() {
	logger, err := logger.GetLogger(false, DSN, "production")
	if err != nil {
		log.Fatal(err)
	}

	//err = sentry.Init(sentry.ClientOptions{
	//	Dsn: DSN,
	//	// Set TracesSampleRate to 1.0 to capture 100%
	//	// of transactions for performance monitoring.
	//	// We recommend adjusting this value in production,
	//	TracesSampleRate: 1.0,
	//})
	//if err != nil {
	//	log.Fatalf("sentry.Init: %s", err)
	//}

	//defer sentry.Flush(2 * time.Second)

	testCounter := promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "teta", Name: "testcounter", Help: "Main endpoint request counter",
	})

	testCounter.Add(1)

	config, err := app.NewConfig(getConfigPath())
	if err != nil {
		logger.Fatal("Error reading app config", zap.Error(err))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	serviceName := "auth"
	serviceVersion := "1.0"
	otelShutdown, err := otelprovider.SetupOTelSDK(ctx, serviceName, serviceVersion)

	defer func() {
		err = errors.Join(err, otelShutdown(context.Background()))
	}()

	a, err := app.New(config, logger, otel.Tracer(TRACER_NAME))
	if err != nil {
		logger.Fatal("Error initializing app", zap.Error(err))
	}

	if err := a.Serve(); err != nil {
		logger.Fatal("Error running app", zap.Error(err))
	}
}
