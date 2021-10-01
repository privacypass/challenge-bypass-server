package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	batgo_kafka "github.com/brave-intl/bat-go/utils/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
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

	consumer := newConsumer(topics, "cbpProcessors", logger)
	var (
		failureCount = 0
		failureLimit = 10
	)
	for {
		// `ReadMessage` blocks until the next event. Do not block main.
		msg, err := consumer.ReadMessage(context.Background())
		if err != nil {
			logger.Error().Msg(err.Error())
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
func newConsumer(topics []string, groupId string, logger *zerolog.Logger) *kafka.Reader {
	var dialer *kafka.Dialer
	brokers = strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	// kafkaCertHack(logger)
	compositeCertString := os.Getenv("KAFKA_SSL_CERTIFICATE")
	os.Setenv("KAFKA_SSL_CERTIFICATE", strings.Replace(compositeCertString, `\n`, "\r", -1))
	if os.Getenv("ENV") != "local" {
		tlsDialer, _, err := batgo_kafka.TLSDialer()
		dialer = tlsDialer
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("Failed to initialize TLS dialer: %e", err))
		}
	}
	logger.Info().Msg(fmt.Sprintf("Subscribing to kafka topic %s on behalf of group %s using brokers %s", topics, groupId, brokers))
	kafkaLogger := logrus.New()
	kafkaLogger.SetLevel(logrus.TraceLevel)
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Dialer:         dialer,
		GroupTopics:    topics,
		GroupID:        groupId,
		StartOffset:    -2,
		ErrorLogger:    kafkaLogger,
		MaxWait:        time.Millisecond * 200,
		CommitInterval: time.Second, // flush commits to Kafka every second
		MinBytes:       1e6,         // 4MB
		MaxBytes:       4e6,         // 4MB
	})
	logger.Info().Msg(fmt.Sprintf("KAFKA READER: %#v", reader))
	return reader
}

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
		key         string
		certificate string
	}
	var compositeCert CompositeCert
	compositeCertString := os.Getenv("KAFKA_SSL_CERTIFICATE")
	if compositeCertString != "" {
		err := json.Unmarshal([]byte(compositeCertString), &compositeCert)
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("Failed to unmarshal KAFKA_SSL_CERTIFICATE. %e", err))
		} else {
			if err := os.WriteFile("/etc/kafka.key", []byte(compositeCert.key), 0666); err != nil {
				logger.Error().Err(err).Msg("")
			} else {
				err = os.Setenv("KAFKA_SSL_KEY_LOCATION", "/etc/kafka.key")
				if err != nil {
					logger.Error().Msg(fmt.Sprintf("Failed to set key location environment variable: %e", err))
				}
			}
			if err := os.WriteFile("/etc/kafka.cert", []byte(compositeCert.certificate), 0666); err != nil {
				logger.Error().Err(err).Msg("")
			} else {
				err = os.Setenv("KAFKA_SSL_CERTIFICATE_LOCATION", "/etc/kafka.cert")
				if err != nil {
					logger.Error().Msg(fmt.Sprintf("Failed to set certificate location environment variable: %e", err))
				}
			}
		}
	}
}
