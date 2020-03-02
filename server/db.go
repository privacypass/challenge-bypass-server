package server

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/brave-intl/challenge-bypass-server/utils/metrics"
	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/lib/pq"
	cache "github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
)

type CachingConfig struct {
	Enabled       bool `json:"enabled"`
	ExpirationSec int  `json:"expirationSec"`
}

type DbConfig struct {
	ConnectionURI string        `json:"connectionURI"`
	CachingConfig CachingConfig `json:"caching"`
	MaxConnection int           `json:"maxConnection"`
}

type Issuer struct {
	IssuerType string
	SigningKey *crypto.SigningKey
	MaxTokens  int
}

type Redemption struct {
	IssuerType string    `json:"issuerType"`
	Id         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Payload    string    `json:"payload"`
}

type CacheInterface interface {
	Get(k string) (interface{}, bool)
	SetDefault(k string, x interface{})
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
		panic(err)
	}
	db.SetMaxOpenConns(cfg.MaxConnection)
	c.db = db

	// Database Telemetry (open connections, etc)
	// Create a new collector, the name will be used as a label on the metrics
	collector := metrics.NewStatsCollector("challenge_bypass_db", db)
	// Register it with Prometheus
	err = prometheus.Register(collector)

	if ae, ok := err.(prometheus.AlreadyRegisteredError); ok {
		// take old collector, and add the new db
		if sc, ok := ae.ExistingCollector.(*metrics.StatsCollector); ok {
			sc.AddStatsGetter("challenge_bypass_db", db)
		}
	}

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		panic(err)
	}
	m, err := migrate.NewWithDatabaseInstance(
		"file:///src/migrations",
		"postgres", driver)
	if err != nil {
		panic(err)
	}
	err = m.Migrate(3)
	if err != migrate.ErrNoChange && err != nil {
		panic(err)
	}

	if cfg.CachingConfig.Enabled {
		c.caches = make(map[string]CacheInterface)
		defaultDuration := time.Duration(cfg.CachingConfig.ExpirationSec) * time.Second
		c.caches["issuers"] = cache.New(defaultDuration, 2*defaultDuration)
		c.caches["redemptions"] = cache.New(defaultDuration, 2*defaultDuration)
	}
}

var (
	fetchIssuerCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fetch_issuer_count",
		Help: "Number of fetch issuer attempts",
	})

	createIssuerCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "create_issuer_count",
		Help: "Number of create issuer attempts",
	})

	redeemTokenCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "redeem_token_count",
		Help: "Number of calls to redeem token",
	})

	fetchRedemptionCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fetch_redemption_count",
		Help: "Number of calls to fetch redemption",
	})

	// Timers for SQL calls
	latencyBuckets = []float64{.25, .5, 1, 2.5, 5, 10}

	fetchIssuerByTypeDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "db_fetch_issuer_by_type_duration",
		Help:    "select issuer by type sql call duration",
		Buckets: latencyBuckets,
	})

	createIssuerDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "db_create_issuer_duration",
		Help:    "create issuer sql call duration",
		Buckets: latencyBuckets,
	})

	createRedemptionDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "db_create_redemption_duration",
		Help:    "create redemption sql call duration",
		Buckets: latencyBuckets,
	})

	fetchRedemptionDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "db_fetch_redemption_duration",
		Help:    "fetch redemption sql call duration",
		Buckets: latencyBuckets,
	})
)

func incrementCounter(c prometheus.Counter) {
	c.Add(1)
}

func (c *Server) fetchIssuer(issuerType string) (*Issuer, error) {
	defer incrementCounter(fetchIssuerCounter)

	if c.caches != nil {
		if cached, found := c.caches["issuers"].Get(issuerType); found {
			return cached.(*Issuer), nil
		}
	}

	queryTimer := prometheus.NewTimer(fetchIssuerByTypeDBDuration)
	rows, err := c.db.Query(
		`SELECT issuer_type, signing_key, max_tokens FROM issuers WHERE issuer_type=$1`, issuerType)
	if err != nil {
		return nil, err
	}
	queryTimer.ObserveDuration()

	defer rows.Close()

	if rows.Next() {
		var signingKey []byte
		var issuer = &Issuer{}
		if err := rows.Scan(&issuer.IssuerType, &signingKey, &issuer.MaxTokens); err != nil {
			return nil, err
		}

		issuer.SigningKey = &crypto.SigningKey{}
		err := issuer.SigningKey.UnmarshalText(signingKey)
		if err != nil {
			return nil, err
		}

		if c.caches != nil {
			c.caches["issuers"].SetDefault(issuerType, issuer)
		}

		return issuer, nil
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nil, IssuerNotFoundError
}

func (c *Server) createIssuer(issuerType string, maxTokens int) error {
	defer incrementCounter(createIssuerCounter)
	if maxTokens == 0 {
		maxTokens = 40
	}

	signingKey, err := crypto.RandomSigningKey()
	if err != nil {
		return err
	}

	signingKeyTxt, err := signingKey.MarshalText()
	if err != nil {
		return err
	}

	queryTimer := prometheus.NewTimer(createIssuerDBDuration)
	rows, err := c.db.Query(
		`INSERT INTO issuers(issuer_type, signing_key, max_tokens) VALUES ($1, $2, $3)`, issuerType, signingKeyTxt, maxTokens)
	if err != nil {
		return err
	}
	queryTimer.ObserveDuration()

	defer rows.Close()
	return nil
}

type Queryable interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

func (c *Server) redeemToken(issuerType string, preimage *crypto.TokenPreimage, payload string) error {
	defer incrementCounter(redeemTokenCounter)
	return redeemTokenWithDB(c.db, issuerType, preimage, payload)
}

func redeemTokenWithDB(db Queryable, issuerType string, preimage *crypto.TokenPreimage, payload string) error {
	preimageTxt, err := preimage.MarshalText()
	if err != nil {
		return err
	}

	queryTimer := prometheus.NewTimer(createRedemptionDBDuration)
	rows, err := db.Query(
		`INSERT INTO redemptions(id, issuer_type, ts, payload) VALUES ($1, $2, NOW(), $3)`, preimageTxt, issuerType, payload)

	queryTimer.ObserveDuration()

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
	defer incrementCounter(fetchRedemptionCounter)
	if c.caches != nil {
		if cached, found := c.caches["redemptions"].Get(fmt.Sprintf("%s:%s", issuerType, id)); found {
			return cached.(*Redemption), nil
		}
	}

	queryTimer := prometheus.NewTimer(fetchRedemptionDBDuration)
	rows, err := c.db.Query(
		`SELECT id, issuer_type, ts, payload FROM redemptions WHERE id = $1 AND issuer_type = $2`, id, issuerType)

	queryTimer.ObserveDuration()

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	if rows.Next() {
		var redemption = &Redemption{}
		if err := rows.Scan(&redemption.Id, &redemption.IssuerType, &redemption.Timestamp, &redemption.Payload); err != nil {
			return nil, err
		}

		if c.caches != nil {
			c.caches["redemptions"].SetDefault(fmt.Sprintf("%s:%s", issuerType, id), redemption)
		}

		return redemption, nil
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nil, RedemptionNotFoundError
}
