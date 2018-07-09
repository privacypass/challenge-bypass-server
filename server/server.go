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
	ListenPort   int    `json:"listen_port,omitempty"`
	MaxTokens    int    `json:"max_tokens,omitempty"`
	DbConfigPath string `json:"db_config_path"`

	dbConfig DbConfig
	db       *sql.DB
	caches   map[string]CacheInterface
}

func (c *Server) ListenAndServe() error {
	c.initDb()

	addr := fmt.Sprintf(":%d", c.ListenPort)

	router := mux.NewRouter()
	c.issuersHandlers(router)
	c.tokensHandlers(router)

	err := http.ListenAndServe(addr, router)
	return err
}
