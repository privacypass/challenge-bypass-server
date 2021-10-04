package kafka

import (
	"context"
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
		env = "staging"
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
	logger.Trace().Msg("Beginning message processing")
	for {
		// `ReadMessage` blocks until the next event. Do not block main.
		msg, err := consumer.ReadMessage(context.Background())
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
func newConsumer(topics []string, groupId string, logger *zerolog.Logger) *kafka.Reader {
	logger.Info().Msg(fmt.Sprintf("Subscribing to kafka topic %s on behalf of group %s using brokers %s", topics, groupId, brokers))
	kafkaLogger := logrus.New()
	kafkaLogger.SetLevel(logrus.TraceLevel)
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Dialer:         getDialer(logger),
		GroupTopics:    topics,
		GroupID:        groupId,
		StartOffset:    -2,
		ErrorLogger:    kafkaLogger,
		MaxWait:        time.Millisecond * 200,
		CommitInterval: time.Second, // flush commits to Kafka every second
		MinBytes:       1e6,         // 4MB
		MaxBytes:       4e6,         // 4MB
	})
	return reader
}

// Emit sends a message over the Kafka interface.
func Emit(topic string, message []byte, logger *zerolog.Logger) error {
	logger.Info().Msg(fmt.Sprintf("Beginning data emission for topic %s", topic))

	if len(brokers) < 1 {
		brokers = strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	}
	conn := kafka.NewWriter(kafka.WriterConfig{
		Brokers: brokers,
		Topic:   topic,
		Dialer:  getDialer(logger),
	})

	err := conn.WriteMessages(
		context.Background(),
		kafka.Message{Value: []byte(message)},
	)
	if err != nil {
		logger.Error().Msg(fmt.Sprintf("Failed to write messages: %e", err))
		return err
	}

	if err = conn.Close(); err != nil {
		logger.Error().Msg(fmt.Sprintf("Failed to close writer: %e", err))
		return err
	}
	logger.Info().Msg("Data emitted")
	return nil
}

func getDialer(logger *zerolog.Logger) *kafka.Dialer {
	var dialer *kafka.Dialer
	brokers = strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	if os.Getenv("ENV") != "local" {
		tlsDialer, _, err := batgo_kafka.TLSDialer()
		dialer = tlsDialer
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("Failed to initialize TLS dialer: %e", err))
		}
	}
	return dialer
}
