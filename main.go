package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/brave-intl/challenge-bypass-server/crypto"
	"github.com/brave-intl/challenge-bypass-server/server"
)

var DefaultServer = &server.Server{
	BindAddress: "127.0.0.1",
	ListenPort:  2416,
	MaxTokens:   100,
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
	errLog          *log.Logger = log.New(os.Stderr, "[btd] ", log.LstdFlags|log.Lshortfile)
	ErrEmptyKeyPath             = errors.New("key file path is empty")
	// Commitments are embedded straight into the extension for now
	ErrEmptyCommPath = errors.New("no commitment file path specified")
)

// loadKeys loads a signing key and optionally loads a file containing old keys for redemption validation
func loadKeys(c *server.Server) error {
	if c.SignKeyFilePath == "" {
		return ErrEmptyKeyPath
	} else if c.CommFilePath == "" {
		return ErrEmptyCommPath
	}

	// Parse current signing key
	_, currkey, err := crypto.ParseKeyFile(c.SignKeyFilePath, true)
	if err != nil {
		return err
	}
	c.SignKey = currkey[0]
	c.RedeemKeys = append(c.RedeemKeys, c.SignKey)

	return nil
}

func main() {
	var configFile string
	var err error
	srv := *DefaultServer

	flag.StringVar(&configFile, "config", "", "local config file for development (overrides cli options)")
	flag.StringVar(&srv.BindAddress, "addr", "127.0.0.1", "address to listen on")
	flag.StringVar(&srv.SignKeyFilePath, "key", "", "path to the current secret key file for signing tokens")
	flag.StringVar(&srv.RedeemKeysFilePath, "redeem_keys", "", "(optional) path to the file containing all other keys that are still used for validating redemptions")
	flag.StringVar(&srv.CommFilePath, "comm", "", "path to the commitment file")
	flag.IntVar(&srv.ListenPort, "p", 2416, "port to listen on")
	flag.IntVar(&srv.MaxTokens, "maxtokens", 100, "maximum number of tokens issued per request")
	flag.Parse()

	if configFile != "" {
		srv, err = loadConfigFile(configFile)
		if err != nil {
			errLog.Fatal(err)
			return
		}
	}

	if configFile == "" && (srv.SignKeyFilePath == "" || srv.CommFilePath == "") {
		flag.Usage()
		return
	}

	err = loadKeys(&srv)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	// Get bytes for public commitment to private key
	GBytes, HBytes, err := crypto.ParseCommitmentFile(srv.CommFilePath)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	srv.GBytes = GBytes
	srv.HBytes = HBytes

	// Retrieve the actual elliptic curve points for the commitment
	// The commitment should match the current key that is being used for signing
	srv.G, srv.H, err = crypto.RetrieveCommPoints(GBytes, HBytes, srv.SignKey)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	err = srv.ListenAndServe()

	if err != nil {
		errLog.Fatal(err)
		return
	}
}
