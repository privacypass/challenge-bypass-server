package server

import (
	"database/sql"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/brave-intl/challenge-bypass-server/crypto"
)

type DbConfig struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Dbname   string `json:"dbname"`
	Host     string `json:"host"`
	Port     string `json:"port"`
}

type Issuer struct {
	IssuerType string
	GBytes     []byte
	HBytes     []byte
	PrivateKey []byte
	MaxTokens  int

	G *crypto.Point
	H *crypto.Point
}

var (
	IssuerNotFoundError = errors.New("Issuer with the given name does not exist")
)

func (c *Server) LoadDbConfig(config DbConfig) {
	c.dbConfig = config
}

func (c *Server) initDb() {
	cfg := c.dbConfig
	db, err := sql.Open("postgres", fmt.Sprintf(
		"user=%s password=%s dbname=%s host=%s port=%s",
		cfg.User, cfg.Password, cfg.Dbname, cfg.Host, cfg.Port))

	if err != nil {
		log.Fatal(err)
	}

	c.db = db
}

func (c *Server) fetchIssuer(issuerType string) (*Issuer, error) {
	rows, err := c.db.Query(
		`SELECT issuerType, G, H, privateKey, maxTokens FROM issuers WHERE issuerType=?`, issuerType)
	defer rows.Close()

	for rows.Next() {
		var G, H, privateKey string
		var issuer = &Issuer{}
		if err := rows.Scan(&issuer.IssuerType, &G, &H, &privateKey, &issuer.MaxTokens); err != nil {
			log.Fatal(err)
			return nil, err
		}

		issuer.GBytes, err = b64.StdEncoding.DecodeString(G)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}

		issuer.HBytes, err = b64.StdEncoding.DecodeString(H)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}

		_, key, err := crypto.ParseKeyString(privateKey, true)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		issuer.PrivateKey = key[0]

		issuer.G, issuer.H, err = crypto.RetrieveCommPoints(issuer.GBytes, issuer.HBytes, issuer.PrivateKey)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}

		return issuer, nil
	}

	if err := rows.Err(); err != nil {
		log.Fatal(err)
		return nil, err
	}

	return nil, IssuerNotFoundError
}

func (c *Server) createIssuer(issuerType string, maxTokens int) error {
	if maxTokens == 0 {
		maxTokens = 40
	}

	privateKey, err := crypto.GeneratePrivateKey(4096)
	if err != nil {
		return err
	}

	curves, keys, err := crypto.ParseKeyString(privateKey, true)
	if err != nil {
		return err
	}

	if len(curves) == 0 || len(keys) == 0 {
		return errors.New("Generated private key does not contain curves or keys")
	}
	curve := curves[0]
	key := keys[0]
	_, G, err := crypto.NewRandomPoint(curve)
	if err != nil {
		return err
	}
	Hx, Hy := curve.ScalarMult(G.X, G.Y, key)
	H, err := crypto.NewPoint(curve, Hx, Hy)
	if err != nil {
		return err
	}

	Gstr := b64.StdEncoding.EncodeToString(G)
	Hstr := b64.StdEncoding.EncodeToString(H)

	rows, err := c.db.Query(
		`INSERT INTO issuers(issuerType, G, H, privateKey, maxTokens) VALUES ($1, $2, $3, $4, $5)`, issuerType, Gstr, Hstr, privateKey, maxTokens)
	defer rows.Close()
	return err
}
