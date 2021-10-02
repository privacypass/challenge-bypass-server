package kafka

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	//	batgo_kafka "github.com/brave-intl/bat-go/utils/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
	//	"github.com/sirupsen/logrus"
)

var brokers []string

type Processor func([]byte, string, *server.Server, *zerolog.Logger)

type TopicMapping struct {
	Topic       string
	ResultTopic string
	Processor   Processor
	Group       string
}

func StartConsumers(server *server.Server, logger *zerolog.Logger) error {
	env := os.Getenv("ENV")
	if env == "" {
		env = "development"
	}
	logger.Info().Msg(fmt.Sprintf("Starting %s Kafka consumers", env))
	topicMappings := []TopicMapping{
		TopicMapping{
			Topic:       "request.redeem.v1." + env + ".cbp",
			ResultTopic: "result.redeem.v1." + env + ".cbp",
			Processor:   SignedTokenRedeemHandler,
			Group:       "cbpProcessors",
		},
		TopicMapping{
			Topic:       "request.sign.v1." + env + ".cbp",
			ResultTopic: "result.sign.v1." + env + ".cbp",
			Processor:   SignedBlindedTokenIssuerHandler,
			Group:       "cbpProcessors",
		},
	}
	var topics []string
	for _, topicMapping := range topicMappings {
		topics = append(topics, topicMapping.Topic)
	}

	// consumer := newConsumer(topics, "cbpProcessors", logger)
	config, err := ParseConfig()
	if err != nil {
		logger.Error().Err(err).Msg("")
	}
	consumer, err := InitializeKafkaReader(config, topics, "cbpProcessors")
	if err != nil {
		logger.Error().Err(err).Msg("")
	}
	var (
		failureCount = 0
		failureLimit = 10
	)
	logger.Trace().Msg("Beginning message processing")
	for {
		// `ReadMessage` blocks until the next event. Do not block main.
		logger.Trace().Msg("Reading message")
		msg, err := consumer.ReadMessage(context.Background())
		logger.Trace().Msg("Message read")
		if err != nil {
			logger.Error().Err(err).Msg("")
			if failureCount > failureLimit {
				break
			}
			failureCount++
			continue
		}
		logger.Info().Msg(fmt.Sprintf("Processing message for topic %s", msg.Topic))
		for _, topicMapping := range topicMappings {
			if msg.Topic == topicMapping.Topic {
				topicMapping.Processor(msg.Value, topicMapping.ResultTopic, server, logger)
			}
		}
	}
	return nil
}

// NewConsumer returns a Kafka reader configured for the given topic and group.
//func newConsumer(topics []string, groupId string, logger *zerolog.Logger) *kafka.Reader {
//	var dialer *kafka.Dialer
//	brokers = strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
//	kafkaCertHack(logger)
//	//compositeCertString := os.Getenv("KAFKA_SSL_CERTIFICATE")
//	//os.Setenv("KAFKA_SSL_CERTIFICATE", strings.Replace(compositeCertString, "\\", "", -1))
//	if os.Getenv("ENV") != "local" {
//		tlsDialer, _, err := batgo_kafka.TLSDialer()
//		dialer = tlsDialer
//		if err != nil {
//			logger.Error().Msg(fmt.Sprintf("Failed to initialize TLS dialer: %e", err))
//		}
//	}
//	logger.Info().Msg(fmt.Sprintf("Subscribing to kafka topic %s on behalf of group %s using brokers %s", topics, groupId, brokers))
//	kafkaLogger := logrus.New()
//	kafkaLogger.SetLevel(logrus.TraceLevel)
//	reader := kafka.NewReader(kafka.ReaderConfig{
//		Brokers:        brokers,
//		Dialer:         dialer,
//		GroupTopics:    topics,
//		GroupID:        groupId,
//		StartOffset:    -2,
//		ErrorLogger:    kafkaLogger,
//		MaxWait:        time.Millisecond * 200,
//		CommitInterval: time.Second, // flush commits to Kafka every second
//		MinBytes:       1e6,         // 4MB
//		MaxBytes:       4e6,         // 4MB
//	})
//	logger.Info().Msg(fmt.Sprintf("KAFKA READER: %#v", reader))
//	return reader
//}

// Emit sends a message over the Kafka interface.
func Emit(topic string, message []byte, logger *zerolog.Logger) error {
	logger.Info().Msg(fmt.Sprintf("Beginning data emission for topic %s", topic))
	partition := 0

	if len(brokers) < 1 {
		return fmt.Errorf("At least one kafka broker must be set")
	}
	conn, err := kafka.DialLeader(context.Background(), "tcp", brokers[0], topic, partition)
	if err != nil {
		logger.Error().Msg(fmt.Sprintf("Failed to dial leader: %e", err))
		return err
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.WriteMessages(
		kafka.Message{Value: []byte(message)},
	)
	if err != nil {
		logger.Error().Msg(fmt.Sprintf("Failed to write messages: %e", err))
		return err
	}

	if err := conn.Close(); err != nil {
		logger.Error().Msg(fmt.Sprintf("Failed to close writer: %e", err))
		return err
	}
	logger.Info().Msg("Data emitted")
	return nil
}

// sensible defaults (used in integration tests)
const (
	DefaultMinBytes       = 1
	DefaultMaxBytes       = 10e6
	DefaultMaxWaitMs      = 1000
	DefaultBackoffStartMs = 1000
)

// InitializeKafkaReader initializes a new kafka reader
func InitializeKafkaReader(conf Config, topics []string, consumerGroup string) (*kafka.Reader, error) {
	sslConfig, err := GenerateSSLConfig(conf.ServerCertificate)
	if err != nil {
		return nil, fmt.Errorf("Error parsing kafka config: %v", err)
	}

	dialer := &kafka.Dialer{
		Timeout:   time.Duration(conf.MaxWaitMs) * time.Millisecond,
		DualStack: true,
		TLS:       sslConfig,
	}

	// tries connection to brokers, since kafka.NewReader() fails silently
	err = TryKafkaConnection(dialer, conf.Brokers)
	if err != nil {
		return nil, fmt.Errorf("Error connecting to Kafka brokers: %v", err)
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Dialer:      dialer,
		Brokers:     conf.Brokers,
		GroupTopics: topics,
		GroupID:     consumerGroup,
		MaxBytes:    conf.MaxBytes,
		MinBytes:    conf.MinBytes,
		MaxWait:     time.Duration(conf.MaxWaitMs) * time.Millisecond,
	})

	return reader, nil
}

// Config has a 1-1 mapping with kafka-go.ReaderConfig for now, since we use
// only kafka (no need to abstract more)
type Config struct {
	Brokers           []string `json:"brokers"`
	MinBytes          int      `json:"min_bytes"`
	MaxBytes          int      `json:"max_bytes"`
	MaxWaitMs         int      `json:"max_wait_ms"`
	ServerCertificate string   `json:"server_certificate"`
}

// ParseConfig parses Kafka configuration from ENV variables, falling
// back to default values
func ParseConfig() (Config, error) {
	b, set := os.LookupEnv("KAFKA_BROKERS")
	brokers := strings.Split(b, ",")
	if !set {
		return Config{}, fmt.Errorf("KAFKA_BROKERS not set")
	}
	cert, set := os.LookupEnv("KAFKA_SSL_CERTIFICATE")
	if !set {
		return Config{}, fmt.Errorf("KAFKA_SSL_CERTIFICATE not set")
	}

	min, set := os.LookupEnv("KAFKA_MIN_BYTES")
	minBytes, err := strconv.Atoi(min)
	if !set || err != nil {
		minBytes = DefaultMinBytes
	}
	max, set := os.LookupEnv("KAFKA_MAX_BYTES")
	maxBytes, err := strconv.Atoi(max)
	if !set || err != nil {
		maxBytes = DefaultMaxBytes
	}
	maxW, set := os.LookupEnv("KAFKA_MAX_WAIT_MS")
	maxWaitMs, err := strconv.Atoi(maxW)
	if !set || err != nil {
		maxWaitMs = DefaultMaxWaitMs
	}

	return Config{
		Brokers:           brokers,
		MinBytes:          minBytes,
		MaxBytes:          maxBytes,
		MaxWaitMs:         maxWaitMs,
		ServerCertificate: cert,
	}, nil
}

// GenerateSSLConfig generates a SSL configuration for connecting to a kafka broker
func GenerateSSLConfig(certString string) (*tls.Config, error) {
	type certConfigs struct {
		Certificate string `json:"certificate"`
		Key         string `json:"key"`
	}
	configs := certConfigs{}
	err := json.Unmarshal([]byte(certString), &configs)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(configs.Certificate))
	if block == nil {
		fmt.Println("Tried to parse SSL certificate:")
		fmt.Println(certString)
		return nil, fmt.Errorf("Kafka SSL certificate is not valid")
	}

	cert, err := tls.X509KeyPair([]byte(configs.Certificate), []byte(configs.Key))
	if err != nil {
		return nil, err
	}

	certs := []tls.Certificate{}
	certs = append(certs, cert)

	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM([]byte(configs.Certificate))
	if !ok {
		return nil, fmt.Errorf("Error setting up TLS configuration: %v ", err)
	}

	return &tls.Config{
		Certificates:       certs,
		RootCAs:            caCertPool,
		InsecureSkipVerify: true,
	}, nil
}

// TryKafkaConnection tries connecting to list of brokers. If at least one
// broker can be reached and connection is successful, error is nil.
// Otherwise, it returns an error describing all connection errors.
func TryKafkaConnection(dialer *kafka.Dialer, brokers []string) error {
	var errors []string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, broker := range brokers {
		_, err := dialer.DialContext(ctx, "tcp", broker)
		if err != nil {
			errors = append(errors, err.Error())
		} else {
			// at least one successful broker connection
			return nil
		}
	}
	return fmt.Errorf("%s", errors)
}

/*
 kafkaCertHack a short-lived hack to allow kafka connections to work in ECS. The ECS task
 definition sets Kafka cert information via a single JSON variable. We parse that and
 persist it to the file and environment variables expected by bat-go.
*/
func kafkaCertHack(logger *zerolog.Logger) {
	caLocation := os.Getenv("KAFKA_SSL_CA_LOCATION")
	if caLocation == "" {
		err := os.Setenv("KAFKA_SSL_CA_LOCATION", "/etc/ssl/certs/ca-certificates.crt")
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("Failed to set ca location environment variable: %e", err))
		}
	}
	type CompositeCert struct {
		Key         string
		Certificate string
	}
	var compositeCert CompositeCert
	compositeCertString := os.Getenv("KAFKA_SSL_CERTIFICATE")
	logger.Trace().Msg(fmt.Sprintf("KAFKA: %s", compositeCertString))
	if compositeCertString != "" {
		err := json.Unmarshal([]byte(compositeCertString), &compositeCert)
		logger.Trace().Msg(fmt.Sprintf("COMPOSITE: %#v", compositeCert))
		logger.Trace().Msg(fmt.Sprintf("COMPOSITE KEY: %s", compositeCert.Key))
		logger.Trace().Msg(fmt.Sprintf("COMPOSITE CERT: %s", compositeCert.Certificate))
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("Failed to unmarshal KAFKA_SSL_CERTIFICATE. %e", err))
		} else {
			if err := os.WriteFile("/etc/kafka.key", []byte(compositeCert.Key), 0666); err != nil {
				logger.Error().Err(err).Msg("")
			} else {
				err = os.Setenv("KAFKA_SSL_KEY_LOCATION", "/etc/kafka.key")
				if err != nil {
					logger.Error().Msg(fmt.Sprintf("Failed to set key location environment variable: %e", err))
				}
			}
			if err := os.WriteFile("/etc/kafka.cert", []byte(compositeCert.Certificate), 0666); err != nil {
				logger.Error().Err(err).Msg("")
			} else {
				err = os.Setenv("KAFKA_SSL_CERTIFICATE_LOCATION", "/etc/kafka.cert")
				if err != nil {
					logger.Error().Msg(fmt.Sprintf("Failed to set certificate location environment variable: %e", err))
				}
			}
		}
		os.Setenv("KAFKA_SSL_CERTIFICATE", "")
	}
}
