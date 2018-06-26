package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/brave-intl/challenge-bypass-server/crypto"
	"github.com/gorilla/mux"
)

var (
	Version         = "dev"
	maxBackoffDelay = 1 * time.Second
	maxRequestSize  = int64(20 * 1024) // ~10kB is expected size for 100*base64([64]byte) + ~framing

	ErrNoSecretKey         = errors.New("server config does not contain a key")
	ErrRequestTooLarge     = errors.New("request too large to process")
	ErrUnrecognizedRequest = errors.New("received unrecognized request type")
)

type Server struct {
	BindAddress        string `json:"bind_address,omitempty"`
	ListenPort         int    `json:"listen_port,omitempty"`
	MaxTokens          int    `json:"max_tokens,omitempty"`
	SignKeyFilePath    string `json:"key_file_path"`
	RedeemKeysFilePath string `json:"redeem_keys_file_path"`
	CommFilePath       string `json:"comm_file_path"`

	SignKey    []byte        // a big-endian marshaled big.Int representing an elliptic curve scalar for the current signing key
	RedeemKeys [][]byte      // current signing key + all old keys
	G          *crypto.Point // elliptic curve point representation of generator G
	H          *crypto.Point // elliptic curve point representation of commitment H to keys[0]

	GBytes []byte
	HBytes []byte
}

func (c *Server) ListenAndServe() error {
	if len(c.SignKey) == 0 {
		return ErrNoSecretKey
	}

	addr := fmt.Sprintf("%s:%d", c.BindAddress, c.ListenPort)

	router := mux.NewRouter()
	router.HandleFunc("/v1/registrar/{type}/", c.registrarHandler).Methods("GET")
	router.HandleFunc("/v1/blindedToken/{type}/", c.blindedTokenIssuerHandler).Methods("POST")
	router.HandleFunc("/v1/blindedToken/{type}/{tokenId}/", c.blindedTokenRedeemHandler).Methods("POST")

	c.issuersHandlers(router)

	err := http.ListenAndServe(addr, router)
	return err
}
