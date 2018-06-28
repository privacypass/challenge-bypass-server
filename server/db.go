package server

import (
	"crypto/elliptic"
	"database/sql"
	b64 "encoding/base64"
	"errors"
	"time"

	"github.com/brave-intl/challenge-bypass-server/crypto"
	"github.com/lib/pq"
)

type DbConfig struct {
	ConnectionURI string `json:"connectionURI"`
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

type Redemption struct {
	IssuerType string    `json:"issuerType"`
	Id         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Payload    string    `json:"payload"`
}

var (
	IssuerNotFoundError      = errors.New("Issuer with the given name does not exist")
	DuplicateRedemptionError = errors.New("Duplicate Redemption")
	RedemptionNotFoundError  = errors.New("Redemption with the given id does not exist")
)

func (c *Server) LoadDbConfig(config DbConfig) {
	c.dbConfig = config
}

func (c *Server) initDb() {
	cfg := c.dbConfig
	db, err := sql.Open("postgres", cfg.ConnectionURI)

	if err != nil {
	}

	c.db = db
}

func (c *Server) fetchIssuer(issuerType string) (*Issuer, error) {
	rows, err := c.db.Query(
		`SELECT issuerType, G, H, privateKey, maxTokens FROM issuers WHERE issuerType=$1`, issuerType)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var G, H, privateKey string
		var issuer = &Issuer{}
		if err := rows.Scan(&issuer.IssuerType, &G, &H, &privateKey, &issuer.MaxTokens); err != nil {
			return nil, err
		}

		issuer.GBytes, err = b64.StdEncoding.DecodeString(G)
		if err != nil {
			return nil, err
		}

		issuer.HBytes, err = b64.StdEncoding.DecodeString(H)
		if err != nil {
			return nil, err
		}

		_, key, err := crypto.ParseKeyString(privateKey, true)
		if err != nil {
			return nil, err
		}
		issuer.PrivateKey = key[0]

		issuer.G, issuer.H, err = crypto.RetrieveCommPoints(issuer.GBytes, issuer.HBytes, issuer.PrivateKey)
		if err != nil {
			return nil, err
		}

		return issuer, nil
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nil, IssuerNotFoundError
}

func (c *Server) createIssuer(issuerType string, maxTokens int) error {
	if maxTokens == 0 {
		maxTokens = 40
	}

	privateKey, err := crypto.GeneratePrivateKey()
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

	Gstr := b64.StdEncoding.EncodeToString(elliptic.Marshal(G.Curve, G.X, G.Y))
	Hstr := b64.StdEncoding.EncodeToString(elliptic.Marshal(H.Curve, H.X, H.Y))

	rows, err := c.db.Query(
		`INSERT INTO issuers(issuerType, G, H, privateKey, maxTokens) VALUES ($1, $2, $3, $4, $5)`, issuerType, Gstr, Hstr, privateKey, maxTokens)
	if err != nil {
		return err
	}

	defer rows.Close()
	return nil
}

func (c *Server) redeemToken(issuerType, id, payload string) error {
	rows, err := c.db.Query(
		`INSERT INTO redemptions(id, issuerType, ts, payload) VALUES ($1, $2, NOW(), $3)`, id, issuerType, payload)

	if err != nil {
		if err, ok := err.(*pq.Error); ok && err.Code == "23505" { // unique constraint violation
			return DuplicateRedemptionError
		}
		return err
	}

	defer rows.Close()
	return nil
}

func (c *Server) fetchRedemption(issuerType, id string) (*Redemption, error) {
	rows, err := c.db.Query(
		`SELECT id, issuerType, ts, payload FROM redemptions WHERE id = $1 AND issuerType = $2`, id, issuerType)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var redemption = &Redemption{}
		if err := rows.Scan(&redemption.Id, &redemption.IssuerType, &redemption.Timestamp, &redemption.Payload); err != nil {
			return nil, err
		}
		return redemption, nil
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nil, RedemptionNotFoundError
}
