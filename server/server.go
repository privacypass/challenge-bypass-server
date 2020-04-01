package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/brave-intl/bat-go/middleware"
	"github.com/go-chi/chi"
	chiware "github.com/go-chi/chi/middleware"
	"github.com/jmoiron/sqlx"
	"github.com/pressly/lg"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

var (
	Version        = "dev"
	maxRequestSize = int64(1024 * 1024) // 1MiB

	ErrNoSecretKey         = errors.New("server config does not contain a key")
	ErrRequestTooLarge     = errors.New("request too large to process")
	ErrUnrecognizedRequest = errors.New("received unrecognized request type")
)

// init - Register Metrics for Server
func init() {
	// DB
	prometheus.MustRegister(fetchIssuerCounter)
	prometheus.MustRegister(createIssuerCounter)
	prometheus.MustRegister(redeemTokenCounter)
	prometheus.MustRegister(fetchRedemptionCounter)
	// DB latency
	prometheus.MustRegister(fetchIssuerByTypeDBDuration)
	prometheus.MustRegister(createIssuerDBDuration)
	prometheus.MustRegister(createRedemptionDBDuration)
	prometheus.MustRegister(fetchRedemptionDBDuration)
}

type Server struct {
	ListenPort   int    `json:"listen_port,omitempty"`
	MaxTokens    int    `json:"max_tokens,omitempty"`
	DbConfigPath string `json:"db_config_path"`
	dynamo       *dynamodb.DynamoDB
	dbConfig     DbConfig
	db           *sqlx.DB

	caches map[string]CacheInterface
}

// DefaultServer on port
var DefaultServer = &Server{
	ListenPort: 2416,
}

// LoadConfigFile loads a file into conf and returns
func LoadConfigFile(filePath string) (Server, error) {
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

// InitDbConfig reads os environment and update conf
func (c *Server) InitDbConfig() error {
	conf := DbConfig{
		DefaultDaysBeforeExpiry: 7,
		DefaultIssuerValidDays:  30,
		MaxConnection:           100,
	}

	// Heroku style
	if connectionURI := os.Getenv("DATABASE_URL"); connectionURI != "" {
		conf.ConnectionURI = os.Getenv("DATABASE_URL")
	}

	if dynamodbEndpoint := os.Getenv("DYNAMODB_ENDPOINT"); dynamodbEndpoint != "" {
		conf.DynamodbEndpoint = os.Getenv("DYNAMODB_ENDPOINT")
	}

	if maxConnection := os.Getenv("MAX_DB_CONNECTION"); maxConnection != "" {
		if count, err := strconv.Atoi(maxConnection); err == nil {
			conf.MaxConnection = count
		}
	}

	if defaultDaysBeforeExpiry := os.Getenv("DEFAULT_DAYS_BEFORE_EXPIRY"); defaultDaysBeforeExpiry != "" {
		if count, err := strconv.Atoi(defaultDaysBeforeExpiry); err == nil {
			conf.DefaultDaysBeforeExpiry = count
		}
	}

	if defaultIssuerValidDays := os.Getenv("DEFAULT_ISSUER_VALID_DAYS"); defaultIssuerValidDays != "" {
		if count, err := strconv.Atoi(defaultIssuerValidDays); err == nil {
			conf.DefaultIssuerValidDays = count
		}
	}

	c.LoadDbConfig(conf)

	return nil
}

// SetupLogger creates a logger to use
func SetupLogger(ctx context.Context) (context.Context, *logrus.Logger) {
	logger := logrus.New()

	//logger.Formatter = &logrus.JSONFormatter{}

	// Redirect output from the standard logging package "log"
	lg.RedirectStdlogOutput(logger)
	lg.DefaultLogger = logger
	ctx = lg.WithLoggerContext(ctx, logger)
	return ctx, logger
}

func (c *Server) setupRouter(ctx context.Context, logger *logrus.Logger) (context.Context, *chi.Mux) {
	c.initDb()
	c.initDynamo()
	c.SetupCronTasks()

	//govalidator.SetFieldsRequiredByDefault(true)

	r := chi.NewRouter()
	r.Use(chiware.RequestID)
	r.Use(chiware.Heartbeat("/"))
	r.Use(chiware.Timeout(60 * time.Second))
	r.Use(middleware.BearerToken)
	if logger != nil {
		// Also handles panic recovery
		r.Use(middleware.RequestLogger(logger))
	}

	r.Mount("/v1/blindedToken", c.tokenRouter())
	r.Mount("/v1/issuer", c.issuerRouter())
	r.Get("/metrics", middleware.Metrics())

	return ctx, r
}

// ListenAndServe listen to ports and mount handlers
func (c *Server) ListenAndServe(ctx context.Context, logger *logrus.Logger) error {
	addr := fmt.Sprintf(":%d", c.ListenPort)
	srv := http.Server{Addr: addr, Handler: chi.ServerBaseContext(c.setupRouter(ctx, logger))}
	return srv.ListenAndServe()
}
