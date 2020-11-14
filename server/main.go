package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/privacypass/challenge-bypass-server"
	"github.com/privacypass/challenge-bypass-server/crypto"
	"github.com/privacypass/challenge-bypass-server/metrics"
)

var (
	Version         = "dev"
	maxBackoffDelay = 1 * time.Second
	maxRequestSize  = int64(20 * 1024) // ~10kB is expected size for 100*base64([64]byte) + ~framing

	ErrEmptyKeyPath        = errors.New("key file path is empty")
	ErrNoSecretKey         = errors.New("server config does not contain a key")
	ErrRequestTooLarge     = errors.New("request too large to process")
	ErrUnrecognizedRequest = errors.New("received unrecognized request type")
	// Commitments are embedded straight into the extension for now
	ErrEmptyCommPath = errors.New("no commitment file path specified")

	errLog *log.Logger = log.New(os.Stderr, "[btd] ", log.LstdFlags|log.Lshortfile)
)

type Server struct {
	BindAddress        string `json:"bind_address,omitempty"`
	ListenPort         int    `json:"listen_port,omitempty"`
	MetricsPort        int    `json:"metrics_port,omitempty"`
	MaxTokens          int    `json:"max_tokens,omitempty"`
	SignKeyFilePath    string `json:"key_file_path"`
	RedeemKeysFilePath string `json:"redeem_keys_file_path"`
	CommFilePath       string `json:"comm_file_path"`

	signKey    []byte        // a big-endian marshaled big.Int representing an elliptic curve scalar for the current signing key
	redeemKeys [][]byte      // current signing key + all old keys
	G          *crypto.Point // elliptic curve point representation of generator G
	H          *crypto.Point // elliptic curve point representation of commitment H to signing key
	keyVersion string        // the version of the key that is used
}

var DefaultServer = &Server{
	BindAddress: "127.0.0.1",
	ListenPort:  2416,
	MetricsPort: 2417,
	MaxTokens:   100,
}

func loadConfigFile(filePath string) (Server, error) {
	conf := *DefaultServer
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return conf, err
	}
	err = json.Unmarshal(data, &conf)
	if err != nil {
		return conf, err
	}
	return conf, nil
}

// return nil to exit without complaint, caller closes
func (c *Server) handle(conn *net.TCPConn) error {
	metrics.CounterConnections.Inc()

	// This is directly in the user's path, an overly slow connection should just fail
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	// Read the request but never more than a worst-case assumption
	var buf = new(bytes.Buffer)
	limitedConn := io.LimitReader(conn, maxRequestSize)
	_, err := io.Copy(buf, limitedConn)

	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "i/o timeout" && buf.Len() > 0 {
			// then probably we just hit the read deadline, so try to unwrap anyway
		} else {
			metrics.CounterConnErrors.Inc()
			return err
		}
	}

	var wrapped btd.BlindTokenRequestWrapper
	var request btd.BlindTokenRequest

	err = json.Unmarshal(buf.Bytes(), &wrapped)
	if err != nil {
		metrics.CounterJsonError.Inc()
		return err
	}
	err = json.Unmarshal(wrapped.Request, &request)
	if err != nil {
		metrics.CounterJsonError.Inc()
		return err
	}

	switch request.Type {
	case btd.ISSUE:
		metrics.CounterIssueTotal.Inc()
		err = btd.HandleIssue(conn, request, c.signKey, c.keyVersion, c.G, c.H, c.MaxTokens)
		if err != nil {
			metrics.CounterIssueError.Inc()
			return err
		}
		return nil
	case btd.REDEEM:
		metrics.CounterRedeemTotal.Inc()
		err = btd.HandleRedeem(conn, request, wrapped.Host, wrapped.Path, c.redeemKeys)
		if err != nil {
			metrics.CounterRedeemError.Inc()
			conn.Write([]byte(err.Error())) // anything other than "success" counts as a VERIFY_ERROR
			return err
		}
		return nil
	default:
		errLog.Printf("unrecognized request type \"%s\"", request.Type)
		metrics.CounterUnknownRequestType.Inc()
		return ErrUnrecognizedRequest
	}
}

// loadKeys loads a signing key and optionally loads a file containing old keys for redemption validation
func (c *Server) loadKeys() error {
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
	c.signKey = currkey[0]
	c.redeemKeys = append(c.redeemKeys, c.signKey)

	// optionally parse old keys that are valid for redemption
	if c.RedeemKeysFilePath != "" {
		errLog.Println("Adding extra keys for verifying token redemptions")
		_, oldKeys, err := crypto.ParseKeyFile(c.RedeemKeysFilePath, false)
		if err != nil {
			return err
		}
		c.redeemKeys = append(c.redeemKeys, oldKeys...)
	}

	return nil
}

func (c *Server) ListenAndServe() error {
	if len(c.signKey) == 0 {
		return ErrNoSecretKey
	}

	addr := fmt.Sprintf("%s:%d", c.BindAddress, c.ListenPort)
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	errLog.Printf("blindsigmgmt starting, version: %v", Version)
	errLog.Printf("listening on %s", addr)

	// Initialize prometheus endpoint
	metricsAddr := fmt.Sprintf("%s:%d", c.BindAddress, c.MetricsPort)
	go func() {
		metrics.RegisterAndListen(metricsAddr, errLog)
	}()

	// Log errors without killing the entire server
	errorChannel := make(chan error)
	go func() {
		for err := range errorChannel {
			if err == nil {
				continue
			}
			errLog.Printf("%v", err)
		}
	}()

	// how long to wait for temporary net errors
	backoffDelay := 1 * time.Millisecond

	for {
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			if netErr, ok := err.(net.Error); ok {
				if netErr.Temporary() {
					// let's wait
					if backoffDelay > maxBackoffDelay {
						backoffDelay = maxBackoffDelay
					}
					time.Sleep(backoffDelay)
					backoffDelay = 2 * backoffDelay
				}
			}
			metrics.CounterConnErrors.Inc()
			errorChannel <- err
			continue
		}

		backoffDelay = 1 * time.Millisecond
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(1 * time.Minute)

		go func() {
			errorChannel <- c.handle(tcpConn)
			tcpConn.Close()
		}()
	}
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
	flag.IntVar(&srv.MetricsPort, "m", 2417, "metrics port")
	flag.IntVar(&srv.MaxTokens, "maxtokens", 100, "maximum number of tokens issued per request")
	flag.StringVar(&srv.keyVersion, "keyversion", "1.0", "version sent to the client for choosing consistent key commitments for proof verification")
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

	err = srv.loadKeys()
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

	// Retrieve the actual elliptic curve points for the commitment
	// The commitment should match the current key that is being used for
	// signing
	//
	// We only support curve point commitments for P256-SHA256
	srv.G, srv.H, err = crypto.RetrieveCommPoints(GBytes, HBytes, srv.signKey)
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
