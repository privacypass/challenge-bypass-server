package server

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

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
	BindAddress  string `json:"bind_address,omitempty"`
	ListenPort   int    `json:"listen_port,omitempty"`
	MaxTokens    int    `json:"max_tokens,omitempty"`
	DbConfigPath string `json:"db_config_path"`

	dbConfig DbConfig
	db       *sql.DB
}

func (c *Server) ListenAndServe() error {
	c.initDb()

	addr := fmt.Sprintf("%s:%d", c.BindAddress, c.ListenPort)

	router := mux.NewRouter()
	router.HandleFunc("/v1/blindedToken/{type}/", c.blindedTokenIssuerHandler).Methods("POST")
	router.HandleFunc("/v1/blindedToken/{type}/{tokenId}/", c.blindedTokenRedeemHandler).Methods("POST")

	c.issuersHandlers(router)
	c.tokensHandlers(router)

	err := http.ListenAndServe(addr, router)
	return err
}
