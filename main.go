package main

import (
	"context"
	"flag"
	"os"
	"strconv"

	"github.com/brave-intl/challenge-bypass-server/server"
	raven "github.com/getsentry/raven-go"
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

	logger.WithFields(logrus.Fields{"prefix": "main"}).Info("Starting server")

	srv.SetupCronTasks()
	
	err = srv.ListenAndServe(serverCtx, logger)

	if err != nil {
		raven.CaptureErrorAndWait(err, nil)
		logger.Panic(err)
		return
	}
}
