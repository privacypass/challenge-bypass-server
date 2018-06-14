package main

import (
	"bytes"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/brave-intl/challenge-bypass-server"
	"github.com/brave-intl/challenge-bypass-server/crypto"
	"github.com/gorilla/mux"
)

type RegistrarResponse struct {
	Name string `json:"name"`
	G    string `json:"G"`
	H    string `json:"H"`
}

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
	MaxTokens          int    `json:"max_tokens,omitempty"`
	SignKeyFilePath    string `json:"key_file_path"`
	RedeemKeysFilePath string `json:"redeem_keys_file_path"`
	CommFilePath       string `json:"comm_file_path"`

	signKey    []byte        // a big-endian marshaled big.Int representing an elliptic curve scalar for the current signing key
	redeemKeys [][]byte      // current signing key + all old keys
	G          *crypto.Point // elliptic curve point representation of generator G
	H          *crypto.Point // elliptic curve point representation of commitment H to keys[0]

	GBytes []byte
	HBytes []byte
}

var DefaultServer = &Server{
	BindAddress: "127.0.0.1",
	ListenPort:  2416,
	MaxTokens:   100,
}

func loadConfigFile(filePath string) (Server, error) {
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

// return nil to exit without complaint, caller closes
func (c *Server) handle(conn *net.TCPConn) error {

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
			return err
		}
	}

	var wrapped btd.BlindTokenRequestWrapper
	var request btd.BlindTokenRequest

	err = json.Unmarshal(buf.Bytes(), &wrapped)
	if err != nil {
		return err
	}
	err = json.Unmarshal(wrapped.Request, &request)
	if err != nil {
		return err
	}

	switch request.Type {
	case btd.ISSUE:
		err = btd.HandleIssue(conn, request, c.signKey, c.G, c.H, c.MaxTokens)
		if err != nil {
			return err
		}
		return nil
	case btd.REDEEM:
		err = btd.HandleRedeem(conn, request, wrapped.Host, wrapped.Path, c.redeemKeys)
		if err != nil {
			conn.Write([]byte(err.Error())) // anything other than "success" counts as a VERIFY_ERROR
			return err
		}
		return nil
	default:
		errLog.Printf("unrecognized request type \"%s\"", request.Type)
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
		_, oldKeys, err := crypto.ParseKeyFile(c.RedeemKeysFilePath, false)
		if err != nil {
			return err
		}
		c.redeemKeys = append(c.redeemKeys, oldKeys...)
	} else {
		errLog.Println("No other keys provided for redeeming older tokens.")
	}

	return nil
}

func (c *Server) registrarHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	json.NewEncoder(w).Encode(RegistrarResponse{vars["type"], b64.StdEncoding.EncodeToString(c.GBytes), b64.StdEncoding.EncodeToString(c.HBytes)})
}

func (c *Server) blindedTokenIssuerHandler(w http.ResponseWriter, r *http.Request) {
	var request btd.BlindTokenRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	marshaledTokenList, err := btd.ApproveTokens(request, c.signKey, c.G, c.H)

	if err != nil {
		http.Error(w, err.Error(), 400)
	}

	// EncodeByteArrays encodes the [][]byte as JSON
	jsonTokenList, err := btd.EncodeByteArrays(marshaledTokenList)
	if err != nil {
		http.Error(w, err.Error(), 400)
	}

	w.Write(jsonTokenList)
}

func (c *Server) blindedTokenRedeemHandler(w http.ResponseWriter, r *http.Request) {
	var request btd.BlindTokenRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	err = btd.RedeemToken(request, []byte{}, []byte{}, c.redeemKeys)
	if err != nil {
		http.Error(w, err.Error(), 400)
	}
}

func (c *Server) ListenAndServe() error {
	if len(c.signKey) == 0 {
		return ErrNoSecretKey
	}

	addr := fmt.Sprintf("%s:%d", c.BindAddress, c.ListenPort)

	router := mux.NewRouter()
	router.HandleFunc("/v1/registrar/{type}/", c.registrarHandler).Methods("GET")
	router.HandleFunc("/v1/blindedToken/{type}/", c.blindedTokenIssuerHandler).Methods("POST")
	router.HandleFunc("/v1/blindedToken/{type}/{tokenId}/", c.blindedTokenRedeemHandler).Methods("POST")

	err := http.ListenAndServe(addr, router)
	return err
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

	srv.GBytes = GBytes
	srv.HBytes = HBytes

	// Retrieve the actual elliptic curve points for the commitment
	// The commitment should match the current key that is being used for signing
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
