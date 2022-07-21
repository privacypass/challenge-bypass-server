package server

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	timeutils "github.com/brave-intl/bat-go/utils/time"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/brave-intl/challenge-bypass-server/utils/metrics"
	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file" // Why?
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	cache "github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// CachingConfig is how long data is cached
type CachingConfig struct {
	Enabled       bool `json:"enabled"`
	ExpirationSec int  `json:"expirationSec"`
}

// DbConfig defines app configurations
type DbConfig struct {
	ConnectionURI           string        `json:"connectionURI"`
	CachingConfig           CachingConfig `json:"caching"`
	MaxConnection           int           `json:"maxConnection"`
	DefaultDaysBeforeExpiry int           `json:"DefaultDaysBeforeExpiry"`
	DefaultIssuerValidDays  int           `json:"DefaultIssuerValidDays"`
	DynamodbEndpoint        string        `json:"DynamodbEndpoint"`
}

type issuer struct {
	ID                   *uuid.UUID  `db:"issuer_id"`
	IssuerType           string      `db:"issuer_type"`
	IssuerCohort         int16       `db:"issuer_cohort"`
	SigningKey           []byte      `db:"signing_key"`
	MaxTokens            int         `db:"max_tokens"`
	CreatedAt            pq.NullTime `db:"created_at"`
	ExpiresAt            pq.NullTime `db:"expires_at"`
	RotatedAt            pq.NullTime `db:"last_rotated_at"`
	Version              int         `db:"version"`
	ValidFrom            *time.Time  `json:"valid_from" db:"valid_from"`
	Buffer               int         `json:"buffer" db:"buffer"`
	DaysOut              int         `json:"days_out" db:"days_out"`
	Overlap              int         `json:"overlap" db:"overlap"`
	Duration             string      `json:"duration" db:"duration"`
	RedemptionRepository string      `json:"-" db:"redemption_repository"`
}

// issuerKeys - an issuer that uses time based keys
type issuerKeys struct {
	ID         *uuid.UUID `db:"key_id"`
	SigningKey []byte     `db:"signing_key"`
	PublicKey  string     `db:"public_key"`
	Cohort     int16      `db:"cohort"`
	IssuerID   *uuid.UUID `db:"issuer_id"`
	CreatedAt  *time.Time `db:"created_at"`
	StartAt    *time.Time `db:"start_at"`
	EndAt      *time.Time `db:"end_at"`
}

// IssuerKeys - an issuer that uses time based keys
type IssuerKeys struct {
	ID         *uuid.UUID         `json:"id"`
	SigningKey *crypto.SigningKey `json:"-"`
	PublicKey  string             `json:"public_key" db:"public_key"`
	Cohort     int16              `json:"cohort" db:"cohort"`
	IssuerID   *uuid.UUID         `json:"issuer_id" db:"issuer_id"`
	CreatedAt  *time.Time         `json:"created_at" db:"created_at"`
	StartAt    *time.Time         `json:"start_at" db:"start_at"`
	EndAt      *time.Time         `json:"end_at" db:"end_at"`
}

// Issuer of tokens
type Issuer struct {
	SigningKey   *crypto.SigningKey
	ID           *uuid.UUID   `json:"id"`
	IssuerType   string       `json:"issuer_type"`
	IssuerCohort int16        `json:"issuer_cohort"`
	MaxTokens    int          `json:"max_tokens"`
	CreatedAt    time.Time    `json:"created_at"`
	ExpiresAt    time.Time    `json:"expires_at"`
	RotatedAt    time.Time    `json:"rotated_at"`
	Version      int          `json:"version"`
	ValidFrom    *time.Time   `json:"valid_from"`
	Buffer       int          `json:"buffer"`
	Overlap      int          `json:"overlap"`
	Duration     string       `json:"duration"`
	Keys         []IssuerKeys `json:"keys"`
}

// Redemption is a token Redeemed
type Redemption struct {
	IssuerType string    `json:"issuerType" db:"issuer_type"`
	ID         string    `json:"id" db:"id"`
	Timestamp  time.Time `json:"timestamp" db:"ts"`
	Payload    string    `json:"payload" db:"payload"`
}

// RedemptionV2 is a token Redeemed
type RedemptionV2 struct {
	IssuerID  string    `json:"issuerId"`
	ID        string    `json:"id"`
	PreImage  string    `json:"preImage"`
	Timestamp time.Time `json:"timestamp"`
	Payload   string    `json:"payload"`
	TTL       int64     `json:"TTL"`
}

// CacheInterface cach functions
type CacheInterface interface {
	Get(k string) (interface{}, bool)
	Delete(k string)
	SetDefault(k string, x interface{})
}

var (
	errIssuerNotFound       = errors.New("Issuer with the given name does not exist")
	errIssuerCohortNotFound = errors.New("Issuer with the given name and cohort does not exist")
	errDuplicateRedemption  = errors.New("Duplicate Redemption")
	errRedemptionNotFound   = errors.New("Redemption with the given id does not exist")
)

// LoadDbConfig loads config into server variable
func (c *Server) LoadDbConfig(config DbConfig) {
	c.dbConfig = config
}

func (c *Server) InitDb() {
	cfg := c.dbConfig

	db, err := sqlx.Open("postgres", cfg.ConnectionURI)
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

	driver, err := postgres.WithInstance(c.db.DB, &postgres.Config{})
	if err != nil {
		panic(err)
	}
	m, err := migrate.NewWithDatabaseInstance(
		"file:///src/migrations",
		"postgres", driver)
	if err != nil {
		panic(err)
	}
	err = m.Migrate(7)
	if err != migrate.ErrNoChange && err != nil {
		panic(err)
	}

	if cfg.CachingConfig.Enabled {
		c.caches = make(map[string]CacheInterface)
		defaultDuration := time.Duration(cfg.CachingConfig.ExpirationSec) * time.Second
		convertedissuersDuration := time.Duration(1 * time.Hour)
		c.caches["issuers"] = cache.New(defaultDuration, 2*defaultDuration)
		c.caches["issuer"] = cache.New(defaultDuration, 2*defaultDuration)
		c.caches["redemptions"] = cache.New(defaultDuration, 2*defaultDuration)
		c.caches["issuercohort"] = cache.New(defaultDuration, 2*defaultDuration)
		c.caches["convertedissuers"] = cache.New(convertedissuersDuration, 2*convertedissuersDuration)
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

	createTimeLimitedIssuerDBDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "db_create_time_limited_issuer_duration",
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

func (c *Server) fetchIssuer(issuerID string) (*Issuer, error) {
	defer incrementCounter(fetchIssuerCounter)

	tx := c.db.MustBegin()
	var err error = nil

	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	if c.caches != nil {
		if cached, found := c.caches["issuer"].Get(issuerID); found {
			return cached.(*Issuer), nil
		}
	}

	fetchedIssuer := issuer{}
	err = tx.Get(&fetchedIssuer, `
	    SELECT * FROM v3_issuers
	    WHERE issuer_id=$1
	`, issuerID)

	if err != nil {
		return nil, errIssuerNotFound
	}

	convertedIssuer, err := c.convertDBIssuer(fetchedIssuer)
	if err != nil {
		return nil, err
	}
	// get the signing keys
	if convertedIssuer.Keys == nil {
		convertedIssuer.Keys = []IssuerKeys{}
	}

	var fetchIssuerKeys = []issuerKeys{}
	err = tx.Select(
		&fetchIssuerKeys,
		`SELECT *
			FROM v3_issuer_keys where issuer_id=$1
			ORDER BY end_at DESC NULLS LAST, start_at DESC`,
		convertedIssuer.ID,
	)
	if err != nil {
		c.Logger.Error("Failed to extract issuer keys from DB")
		return nil, err
	}

	for _, v := range fetchIssuerKeys {
		k, err := c.convertDBIssuerKeys(v)
		if err != nil {
			c.Logger.Error("Failed to convert issuer keys from DB")
			return nil, err
		}
		convertedIssuer.Keys = append(convertedIssuer.Keys, *k)
	}

	if c.caches != nil {
		c.caches["issuer"].SetDefault(issuerID, *convertedIssuer)
	}

	return convertedIssuer, nil
}

func (c *Server) fetchIssuersByCohort(issuerType string, issuerCohort int16) (*[]Issuer, error) {
	// will not lose resolution int16->int
	compositeCacheKey := issuerType + strconv.Itoa(int(issuerCohort))
	if c.caches != nil {
		if cached, found := c.caches["issuercohort"].Get(compositeCacheKey); found {
			return cached.(*[]Issuer), nil
		}
	}

	tx := c.db.MustBegin()
	var err error = nil

	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	fetchedIssuers := []issuer{}
	err = tx.Select(
		&fetchedIssuers,
		`SELECT i.*
		FROM v3_issuers i join v3_issuer_keys k on (i.issuer_id=k.issuer_id)
		WHERE i.issuer_type=$1 AND k.cohort=$2
		ORDER BY i.expires_at DESC NULLS LAST, i.created_at DESC`, issuerType, issuerCohort)
	if err != nil {
		return nil, err
	}

	if len(fetchedIssuers) < 1 {
		return nil, errIssuerCohortNotFound
	}

	issuers := []Issuer{}
	for _, fetchedIssuer := range fetchedIssuers {
		convertedIssuer, err := c.convertDBIssuer(fetchedIssuer)
		if err != nil {
			return nil, err
		}
		// get the keys for the Issuer
		if convertedIssuer.Keys == nil {
			convertedIssuer.Keys = []IssuerKeys{}
		}

		var fetchIssuerKeys = []issuerKeys{}
		err = tx.Select(
			&fetchIssuerKeys,
			`SELECT *
			FROM v3_issuer_keys where issuer_id=$1
			ORDER BY end_at DESC NULLS LAST, start_at DESC`,
			convertedIssuer.ID,
		)
		if err != nil {
			c.Logger.Error("Failed to extract issuer keys from DB")
			return nil, err
		}

		for _, v := range fetchIssuerKeys {
			k, err := c.convertDBIssuerKeys(v)
			if err != nil {
				c.Logger.Error("Failed to convert issuer keys from DB")
				return nil, err
			}
			convertedIssuer.Keys = append(convertedIssuer.Keys, *k)
		}

		issuers = append(issuers, *convertedIssuer)
	}

	if c.caches != nil {
		c.caches["issuercohort"].SetDefault(compositeCacheKey, issuers)
	}

	return &issuers, nil
}

func (c *Server) fetchIssuers(issuerType string) (*[]Issuer, error) {
	if c.caches != nil {
		if cached, found := c.caches["issuers"].Get(issuerType); found {
			return cached.(*[]Issuer), nil
		}
	}

	tx := c.db.MustBegin()
	var err error = nil

	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	fetchedIssuers := []issuer{}
	err = tx.Select(
		&fetchedIssuers,
		`SELECT *
		FROM v3_issuers
		WHERE issuer_type=$1
		ORDER BY expires_at DESC NULLS LAST, created_at DESC`, issuerType)
	if err != nil {
		return nil, err
	}

	if len(fetchedIssuers) < 1 {
		return nil, errIssuerNotFound
	}

	issuers := []Issuer{}
	for _, fetchedIssuer := range fetchedIssuers {
		convertedIssuer, err := c.convertDBIssuer(fetchedIssuer)
		if err != nil {
			return nil, err
		}
		// get the keys for the Issuer
		if convertedIssuer.Keys == nil {
			convertedIssuer.Keys = []IssuerKeys{}
		}

		var fetchIssuerKeys = []issuerKeys{}
		err = tx.Select(
			&fetchIssuerKeys,
			`SELECT *
			FROM v3_issuer_keys where issuer_id=$1
			ORDER BY end_at DESC NULLS LAST, start_at DESC`,
			convertedIssuer.ID,
		)
		if err != nil {
			c.Logger.Error("Failed to extract issuer keys from DB")
			return nil, err
		}

		for _, v := range fetchIssuerKeys {
			k, err := c.convertDBIssuerKeys(v)
			if err != nil {
				c.Logger.Error("Failed to convert issuer keys from DB")
				return nil, err
			}
			convertedIssuer.Keys = append(convertedIssuer.Keys, *k)
		}

		issuers = append(issuers, *convertedIssuer)
	}

	if c.caches != nil {
		c.caches["issuers"].SetDefault(issuerType, issuers)
	}

	return &issuers, nil
}

func (c *Server) FetchAllIssuers() (*[]Issuer, error) {
	tx := c.db.MustBegin()
	var err error = nil

	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()
	fetchedIssuers := []issuer{}
	err = tx.Select(
		&fetchedIssuers,
		`SELECT *
		FROM v3_issuers
		ORDER BY expires_at DESC NULLS LAST, created_at DESC`)
	if err != nil {
		c.Logger.Error("Failed to extract issuers from DB")
		return nil, err
	}

	issuers := []Issuer{}
	for _, fetchedIssuer := range fetchedIssuers {
		convertedIssuer, err := c.convertDBIssuer(fetchedIssuer)
		if err != nil {
			c.Logger.Error("Error converting extracted Issuer")
			return nil, err
		}

		if convertedIssuer.Keys == nil {
			convertedIssuer.Keys = []IssuerKeys{}
		}

		var fetchIssuerKeys = []issuerKeys{}
		err = tx.Select(
			&fetchIssuerKeys,
			`SELECT *
			FROM v3_issuer_keys where issuer_id=$1
			ORDER BY end_at DESC NULLS LAST, start_at DESC`,
			convertedIssuer.ID,
		)
		if err != nil {
			c.Logger.Error("Failed to extract issuer keys from DB")
			return nil, err
		}

		for _, v := range fetchIssuerKeys {
			k, err := c.convertDBIssuerKeys(v)
			if err != nil {
				c.Logger.Error("Failed to convert issuer keys from DB")
				return nil, err
			}
			convertedIssuer.Keys = append(convertedIssuer.Keys, *k)
		}

		issuers = append(issuers, *convertedIssuer)
	}

	return &issuers, nil
}

// RotateIssuers is the function that rotates
func (c *Server) rotateIssuers() error {
	cfg := c.dbConfig

	tx := c.db.MustBegin()

	var err error = nil

	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	fetchedIssuers := []issuer{}
	err = tx.Select(
		&fetchedIssuers,
		`SELECT * FROM v3_issuers
			WHERE expires_at IS NOT NULL
			AND last_rotated_at < NOW() - $1 * INTERVAL '1 day'
			AND expires_at < NOW() + $1 * INTERVAL '1 day'
			AND version >= 2
		FOR UPDATE SKIP LOCKED`, cfg.DefaultDaysBeforeExpiry,
	)
	if err != nil {
		return err
	}

	for _, v := range fetchedIssuers {
		// converted
		issuer, err := c.convertDBIssuer(v)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to convert rows on v3 issuer creation: %w", err)
		}
		// populate keys in db
		if err := txPopulateIssuerKeys(c.Logger, tx, *issuer); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to populate v3 issuer keys: %w", err)
		}

		if _, err = tx.Exec(
			`UPDATE v3_issuers SET last_rotated_at = now() where issuer_id = $1`,
			issuer.ID,
		); err != nil {
			return err
		}
	}

	return nil
}

// rotateIssuers is the function that rotates
func (c *Server) rotateIssuersV3() error {

	tx := c.db.MustBegin()

	var err error = nil

	defer func() {
		if err != nil {
			err = tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	fetchedIssuers := []Issuer{}

	// we need to get all of the v3 issuers that
	// 1. are not expired
	// 2. now is after valid_from
	// 3. have max(issuer_v3.end_at) < buffer

	err = tx.Select(
		&fetchedIssuers,
		`
			select
				i.id, i.issuer_type, i.issuer_cohort, i.max_tokens, i.version,
				i.buffer, i.valid_from, i.last_rotated_at, i.expires_at, i.duration,
				i.created_at
			from
				v3_issuers i
				join v3_issuer_keys ik on (ik.issuer_id = i.issuer_id)
			where
				i.version = 3
				and i.expires_at is not null and i.expires_at < now()
				and greatest(ik.end_at) < now() + i.buffer * i.duration::interval
			for update skip locked
		`,
	)
	if err != nil {
		return err
	}

	// for each issuer fetched
	for _, issuer := range fetchedIssuers {
		// populate the buffer of keys for the v3 issuer
		if err := txPopulateIssuerKeys(c.Logger, tx, issuer); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to close rows on v3 issuer creation: %w", err)
		}
		// denote that the v3 issuer was rotated at this time
		if _, err = tx.Exec(
			`UPDATE v3_issuers SET last_rotated_at = now() where issuer_id = $1`,
			issuer.ID,
		); err != nil {
			return err
		}
	}

	return nil
}

// createIssuer - creation of a v3 issuer
func (c *Server) createV3Issuer(issuer Issuer) error {
	defer incrementCounter(createIssuerCounter)
	if issuer.MaxTokens == 0 {
		issuer.MaxTokens = 40
	}

	tx := c.db.MustBegin()

	queryTimer := prometheus.NewTimer(createTimeLimitedIssuerDBDuration)
	row := tx.QueryRowx(
		`
		INSERT INTO v3_issuers
			(
				issuer_type,
				issuer_cohort,
				max_tokens,
				version,
				expires_at,
				buffer,
				duration)
		VALUES
		($1, $2, $3, $4, $5, $6, $7)
		RETURNING issuer_id`,
		issuer.IssuerType,
		issuer.IssuerCohort,
		issuer.MaxTokens,
		issuer.Version,
		issuer.ExpiresAt,
		issuer.Buffer,
		issuer.Duration,
	)

	// get the newly inserted issuer identifier
	if err := row.Scan(&issuer.ID); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to get v3 issuer id: %w", err)
	}

	if err := txPopulateIssuerKeys(c.Logger, tx, issuer); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to close rows on v3 issuer creation: %w", err)
	}
	queryTimer.ObserveDuration()
	return tx.Commit()
}

// on the transaction, populate v3 issuer keys for the v3 issuer
func txPopulateIssuerKeys(logger *logrus.Logger, tx *sqlx.Tx, issuer Issuer) error {
	var (
		duration *timeutils.ISODuration
		err      error
	)

	if issuer.Version == 3 {
		// get the duration from the issuer
		duration, err = timeutils.ParseDuration(issuer.Duration)
		if err != nil {
			return fmt.Errorf("failed to parse issuer duration: %w", err)
		}
	}

	// v1/v2 issuers only have a buffer of 1
	if issuer.Version < 3 {
		issuer.Buffer = 1
	}

	var tmp time.Time
	if issuer.ValidFrom != nil {
		tmp = *issuer.ValidFrom
	}
	start := &tmp

	i := 0
	// time to create the keys associated with the issuer
	if issuer.Keys == nil || len(issuer.Keys) == 0 {
		issuer.Keys = []IssuerKeys{}
	} else {
		// if the issuer has keys already, start needs to be the last item in slice
		start = issuer.Keys[len(issuer.Keys)-1].EndAt
		i = len(issuer.Keys)
	}

	valueFmtStr := ""

	var keys = []issuerKeys{}
	var position = 0
	// for i in buffer, create signing keys for each
	for ; i < issuer.Buffer; i++ {
		end := new(time.Time)
		if duration != nil {
			// start/end, increment every iteration
			end, err = duration.From(*start)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("unable to calculate end time: %w", err)
			}
		}

		signingKey, err := crypto.RandomSigningKey()
		if err != nil {
			logger.Error("Error generating key")
			tx.Rollback()
			return err
		}

		signingKeyTxt, err := signingKey.MarshalText()
		if err != nil {
			logger.Error("Error marshalling signing key")
			tx.Rollback()
			return err
		}

		pubKeyTxt, err := signingKey.PublicKey().MarshalText()
		if err != nil {
			logger.Error("Error marshalling public key")
			tx.Rollback()
			return err
		}

		keys = append(keys, issuerKeys{
			SigningKey: signingKeyTxt,
			PublicKey:  string(pubKeyTxt),
			Cohort:     issuer.IssuerCohort,
			IssuerID:   issuer.ID,
			StartAt:    start,
			EndAt:      end,
		})

		if issuer.ValidFrom != nil && !(*start).Equal(*issuer.ValidFrom) {
			valueFmtStr += ", "
		}
		valueFmtStr += fmt.Sprintf("($%d, $%d, $%d, $%d, $%d, $%d)",
			position+1,
			position+2,
			position+3,
			position+4,
			position+5,
			position+6)

		// next set of position parameter start
		position += 6

		// increment start
		if start != nil && end != nil {
			*start = *end
		}
	}

	var values []interface{}
	// create our value params for insertion
	for _, v := range keys {
		values = append(values,
			v.IssuerID, v.SigningKey, v.PublicKey, v.Cohort, v.StartAt, v.EndAt)
	}

	rows, err := tx.Query(
		fmt.Sprintf(`
		INSERT INTO v3_issuer_keys
			(
				issuer_id,
				signing_key,
				public_key,
				cohort,
				start_at,
				end_at
			)
		VALUES %s`, valueFmtStr), values...)
	if err != nil {
		logger.Error("Could not insert the new issuer keys into the DB")
		tx.Rollback()
		return err
	}
	return rows.Close()
}

func (c *Server) createIssuerV2(issuerType string, issuerCohort int16, maxTokens int, expiresAt *time.Time) error {
	defer incrementCounter(createIssuerCounter)
	if maxTokens == 0 {
		maxTokens = 40
	}

	// convert to a v3 issuer
	return c.createV3Issuer(Issuer{
		IssuerType:   issuerType,
		IssuerCohort: issuerCohort,
		Version:      2,
		MaxTokens:    maxTokens,
		ExpiresAt:    *expiresAt,
	})
}

func (c *Server) createIssuer(issuerType string, issuerCohort int16, maxTokens int, expiresAt *time.Time) error {
	defer incrementCounter(createIssuerCounter)
	if maxTokens == 0 {
		maxTokens = 40
	}

	// convert to a v3 issuer
	return c.createV3Issuer(Issuer{
		IssuerType:   issuerType,
		IssuerCohort: issuerCohort,
		Version:      1,
		MaxTokens:    maxTokens,
		ExpiresAt:    *expiresAt,
	})
}

type Queryable interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

func (c *Server) RedeemToken(issuerForRedemption *Issuer, preimage *crypto.TokenPreimage, payload string) error {
	defer incrementCounter(redeemTokenCounter)
	if issuerForRedemption.Version == 1 {
		return redeemTokenWithDB(c.db, issuerForRedemption.IssuerType, preimage, payload)
	} else if issuerForRedemption.Version == 2 || issuerForRedemption.Version == 3 {
		return c.redeemTokenWithDynamo(issuerForRedemption, preimage, payload)
	}
	return errors.New("Wrong Issuer Version")
}

func redeemTokenWithDB(db Queryable, stringIssuer string, preimage *crypto.TokenPreimage, payload string) error {
	preimageTxt, err := preimage.MarshalText()
	if err != nil {
		return err
	}

	queryTimer := prometheus.NewTimer(createRedemptionDBDuration)
	rows, err := db.Query(
		`INSERT INTO redemptions(id, issuer_type, ts, payload) VALUES ($1, $2, NOW(), $3)`, preimageTxt, stringIssuer, payload)
	defer func() error {
		if rows != nil {
			err := rows.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}()
	if err != nil {
		if err, ok := err.(*pq.Error); ok && err.Code == "23505" { // unique constraint violation
			return errDuplicateRedemption
		}
		return err
	}

	queryTimer.ObserveDuration()
	return nil
}

func (c *Server) fetchRedemption(issuerType, ID string) (*Redemption, error) {
	defer incrementCounter(fetchRedemptionCounter)
	if c.caches != nil {
		if cached, found := c.caches["redemptions"].Get(fmt.Sprintf("%s:%s", issuerType, ID)); found {
			return cached.(*Redemption), nil
		}
	}

	queryTimer := prometheus.NewTimer(fetchRedemptionDBDuration)
	rows, err := c.db.Query(
		`SELECT id, issuer_id, ts, payload FROM redemptions WHERE id = $1 AND issuer_type = $2`, ID, issuerType)
	queryTimer.ObserveDuration()

	if err != nil {
		c.Logger.Error("Unable to perform the query")
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		var redemption = &Redemption{}
		if err := rows.Scan(&redemption.ID, &redemption.IssuerType, &redemption.Timestamp, &redemption.Payload); err != nil {
			c.Logger.Error("Unable to convert DB values into redemption data structure")
			return nil, err
		}

		if c.caches != nil {
			c.caches["redemptions"].SetDefault(fmt.Sprintf("%s:%s", issuerType, ID), redemption)
		}

		return redemption, nil
	}

	if err := rows.Err(); err != nil {
		c.Logger.Error("Error parsing rows of DB")
		return nil, err
	}

	c.Logger.Error("Redemption not found")
	return nil, errRedemptionNotFound
}

func (c *Server) convertDBIssuerKeys(issuerKeyToConvert issuerKeys) (*IssuerKeys, error) {
	stringifiedSigningKey := string(issuerKeyToConvert.SigningKey)
	if c.caches != nil {
		if cached, found := c.caches["convertedissuerkeyss"].Get(stringifiedSigningKey); found {
			return cached.(*IssuerKeys), nil
		}
	}
	parsedIssuerKeys, err := parseIssuerKeys(issuerKeyToConvert)
	if err != nil {
		return nil, err
	}
	if c.caches != nil {
		c.caches["issuerkeys"].SetDefault(stringifiedSigningKey, parseIssuerKeys)
	}
	return &parsedIssuerKeys, nil
}

func (c *Server) convertDBIssuer(issuerToConvert issuer) (*Issuer, error) {
	stringifiedID := string(issuerToConvert.ID.String())
	if c.caches != nil {
		if cached, found := c.caches["convertedissuers"].Get(stringifiedID); found {
			return cached.(*Issuer), nil
		}
	}
	parsedIssuer, err := parseIssuer(issuerToConvert)
	if err != nil {
		return nil, err
	}
	if c.caches != nil {
		c.caches["issuer"].SetDefault(stringifiedID, parseIssuer)
	}
	return &parsedIssuer, nil
}

func parseIssuerKeys(issuerKeysToParse issuerKeys) (IssuerKeys, error) {
	parsedIssuerKey := IssuerKeys{
		ID:        issuerKeysToParse.ID,
		Cohort:    issuerKeysToParse.Cohort,
		CreatedAt: issuerKeysToParse.CreatedAt,
		StartAt:   issuerKeysToParse.StartAt,
		EndAt:     issuerKeysToParse.EndAt,
		IssuerID:  issuerKeysToParse.IssuerID,
		PublicKey: issuerKeysToParse.PublicKey,
	}

	parsedIssuerKey.SigningKey = &crypto.SigningKey{}
	err := parsedIssuerKey.SigningKey.UnmarshalText(issuerKeysToParse.SigningKey)
	if err != nil {
		return IssuerKeys{}, err
	}
	return parsedIssuerKey, nil
}

func parseIssuer(issuerToParse issuer) (Issuer, error) {
	parsedIssuer := Issuer{
		ID:           issuerToParse.ID,
		IssuerType:   issuerToParse.IssuerType,
		IssuerCohort: issuerToParse.IssuerCohort,
		MaxTokens:    issuerToParse.MaxTokens,
		Version:      issuerToParse.Version,
	}
	if issuerToParse.ExpiresAt.Valid {
		parsedIssuer.ExpiresAt = issuerToParse.ExpiresAt.Time
	}
	if issuerToParse.CreatedAt.Valid {
		parsedIssuer.CreatedAt = issuerToParse.CreatedAt.Time
	}
	if issuerToParse.RotatedAt.Valid {
		parsedIssuer.RotatedAt = issuerToParse.RotatedAt.Time
	}

	return parsedIssuer, nil
}
