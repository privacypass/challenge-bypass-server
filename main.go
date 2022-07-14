package main

import (
	"context"
	"flag"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"

	"github.com/brave-intl/challenge-bypass-server/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	raven "github.com/getsentry/raven-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Server setup
	var configFile string
	var err error

	serverCtx, logger := server.SetupLogger(context.Background())
	zeroLogger := zerolog.New(os.Stderr).With().Timestamp().Caller().Logger()
	if os.Getenv("ENV") != "production" {
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	}

	srv := *server.DefaultServer

	flag.StringVar(&configFile, "config", "", "local config file for development (overrides cli options)")
	flag.StringVar(&srv.DbConfigPath, "db_config", "", "path to the json file with database configuration")
	flag.IntVar(&srv.ListenPort, "p", 2416, "port to listen on")
	flag.Parse()

	if configFile != "" {
		srv, err = server.LoadConfigFile(configFile)
		if err != nil {
			logger.Panic(err)
			return
		}
	}

	if port := os.Getenv("PORT"); port != "" {
		if portNumber, err := strconv.Atoi(port); err == nil {
			srv.ListenPort = portNumber
		}
	}

	err = srv.InitDbConfig()
	if err != nil {
		logger.Panic(err)
	}

	zeroLogger.Trace().Msg("Initializing persistence and cron jobs")

	// Initialize databases and cron tasks before the Kafka processors and server start
	srv.InitDb()
	srv.InitDynamo()
	// Run the cron job unless it's explicitly disabled.
	if os.Getenv("CRON_ENABLED") != "false" {
		srv.SetupCronTasks()
	}

	zeroLogger.Trace().Msg("Persistence and cron jobs initialized")

	// add profiling flag to enable profiling routes
	if os.Getenv("PPROF_ENABLE") != "" {
		zeroLogger.Trace().Msg("Enabling PPROF")
		var addr = ":6061"
		if os.Getenv("PPROF_PORT") != "" {
			addr = os.Getenv("PPROF_PORT")
		}

		// pprof attaches routes to default serve mux
		// host:6061/debug/pprof/
		go func() {
			log.Error().Err(http.ListenAndServe(addr, http.DefaultServeMux))
		}()
	}

	if os.Getenv("KAFKA_ENABLED") != "false" {
		zeroLogger.Trace().Msg("Spawning Kafka goroutine")
		go func() {
			zeroLogger.Trace().Msg("Initializing Kafka consumers")
			err = kafka.StartConsumers(&srv, &zeroLogger)

			if err != nil {
				zeroLogger.Error().Err(err).Msg("Failed to initialize Kafka consumers")
				return
			}
		}()
	}

	zeroLogger.Trace().Msg("Initializing API server")

	err = srv.ListenAndServe(serverCtx, logger)

	if err != nil {
		zeroLogger.Error().Err(err).Msg("Failed to initialize API server")
		raven.CaptureErrorAndWait(err, nil)
		logger.Panic(err)
		return
	}
}
