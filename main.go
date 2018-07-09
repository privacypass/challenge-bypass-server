package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/brave-intl/challenge-bypass-server/server"
)

var DefaultServer = &server.Server{
	ListenPort: 2416,
}

func loadConfigFile(filePath string) (server.Server, error) {
	conf := *DefaultServer
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return conf, err
	}
	err = json.Unmarshal(data, conf)
	if err != nil {
		return conf, err
	}
	return conf, nil
}

var (
	errLog               *log.Logger = log.New(os.Stderr, "[btd] ", log.LstdFlags|log.Lshortfile)
	ErrEmptyDbConfigPath             = errors.New("no db config path specified")
)

func loadDbConfig(c *server.Server) error {
	conf := server.DbConfig{}
	var data []byte

	if envConfig := os.Getenv("DBCONFIG"); envConfig != "" {
		data = []byte(envConfig)
	} else {
		if c.DbConfigPath == "" {
			return ErrEmptyDbConfigPath
		}

		var err error
		data, err = ioutil.ReadFile(c.DbConfigPath)
		if err != nil {
			return err
		}
	}

	json.Unmarshal(data, &conf)
	c.LoadDbConfig(conf)

	return nil
}

func main() {
	var configFile string
	var err error
	srv := *DefaultServer

	flag.StringVar(&configFile, "config", "", "local config file for development (overrides cli options)")
	flag.StringVar(&srv.DbConfigPath, "db_config", "", "path to the json file with database configuration")
	flag.IntVar(&srv.ListenPort, "p", 2416, "port to listen on")
	flag.Parse()

	if configFile != "" {
		srv, err = loadConfigFile(configFile)
		if err != nil {
			errLog.Fatal(err)
			return
		}
	}

	if port := os.Getenv("PORT"); port != "" {
		if portNumber, err := strconv.Atoi(port); err == nil {
			srv.ListenPort = portNumber
		}
	}

	err = loadDbConfig(&srv)
	if err != nil {
		errLog.Fatal(err)
	}

	err = srv.ListenAndServe()

	if err != nil {
		errLog.Fatal(err)
		return
	}
}
