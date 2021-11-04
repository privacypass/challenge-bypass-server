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
	"github.com/sirupsen/logrus"
)

func main() {
	// Server setup
	var configFile string
	var err error

	serverCtx, logger := server.SetupLogger(context.Background())

	logger.WithFields(logrus.Fields{"prefix": "main"}).Info("Loading config")

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

	// Initialize databases and cron tasks before the Kafka processors and server start
	srv.InitDb()
	srv.InitDynamo()
	srv.SetupCronTasks()

	logger.WithFields(logrus.Fields{"prefix": "main"}).Info("Starting server")

	// add profiling flag to enable profiling routes
	if os.Getenv("PPROF_ENABLE") != "" {
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

	go func() {
		zeroLogger := zerolog.New(os.Stderr).With().Timestamp().Caller().Logger()
		if os.Getenv("ENV") != "production" {
			zerolog.SetGlobalLevel(zerolog.TraceLevel)
		}
		err = kafka.StartConsumers(&srv, &zeroLogger)

		if err != nil {
			zeroLogger.Error().Err(err).Msg("")
			return
		}
	}()

//	err = srv.ListenAndServe(serverCtx, logger)
//
//	if err != nil {
//		raven.CaptureErrorAndWait(err, nil)
//		logger.Panic(err)
//		return
//	}
}
