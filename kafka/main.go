package kafka

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	batgo_kafka "github.com/brave-intl/bat-go/utils/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	uuid "github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
)

var brokers []string

type Processor func([]byte, *kafka.Writer, *server.Server, *zerolog.Logger) error

type TopicMapping struct {
	Topic          string
	ResultProducer *kafka.Writer
	Processor      Processor
	Group          string
}

func StartConsumers(providedServer *server.Server, logger *zerolog.Logger) error {
	adsRequestRedeemV1Topic := os.Getenv("REDEEM_CONSUMER_TOPIC")
	adsResultRedeemV1Topic := os.Getenv("REDEEM_PRODUCER_TOPIC")
	adsRequestSignV1Topic := os.Getenv("SIGN_CONSUMER_TOPIC")
	adsResultSignV1Topic := os.Getenv("SIGN_PRODUCER_TOPIC")
	adsConsumerGroupV1 := os.Getenv("CONSUMER_GROUP")
	if len(brokers) < 1 {
		brokers = strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	}
	topicMappings := []TopicMapping{
		TopicMapping{
			Topic: adsRequestRedeemV1Topic,
			ResultProducer: kafka.NewWriter(kafka.WriterConfig{
				Brokers: brokers,
				Topic:   adsResultRedeemV1Topic,
				Dialer:  getDialer(logger),
			}),
			Processor: SignedTokenRedeemHandler,
			Group:     adsConsumerGroupV1,
		},
		TopicMapping{
			Topic: adsRequestSignV1Topic,
			ResultProducer: kafka.NewWriter(kafka.WriterConfig{
				Brokers: brokers,
				Topic:   adsResultSignV1Topic,
				Dialer:  getDialer(logger),
			}),
			Processor: SignedBlindedTokenIssuerHandler,
			Group:     adsConsumerGroupV1,
		},
	}
	var topics []string
	for _, topicMapping := range topicMappings {
		topics = append(topics, topicMapping.Topic)
	}

	consumerCount, err := strconv.Atoi(os.Getenv("KAFKA_CONSUMERS_PER_NODE"))
	if err != nil {
		logger.Error().Err(err).Msg("Failed to convert KAFKA_CONSUMERS_PER_NODE variable to a usable integer. Defaulting to 1.")
		consumerCount = 1
	}

	logger.Trace().Msg(fmt.Sprintf("Spawning %d consumer goroutines", consumerCount))

	for i := 1; i <= consumerCount; i++ {
		go func(topicMappings []TopicMapping) {
			consumer := newConsumer(topics, adsConsumerGroupV1, logger)
			var (
				failureCount = 0
				failureLimit = 10
			)
			logger.Trace().Msg("Beginning message processing")
			for {
				// `FetchMessage` blocks until the next event. Do not block main.
				ctx := context.Background()
				logger.Trace().Msg(fmt.Sprintf("Fetching messages from Kafka"))
				msg, err := consumer.FetchMessage(ctx)
				if err != nil {
					logger.Error().Err(err).Msg("")
					if failureCount > failureLimit {
						break
					}
					failureCount++
					continue
				}
				logger.Info().Msg(fmt.Sprintf("Processing message for topic %s at offset %d", msg.Topic, msg.Offset))
				logger.Info().Msg(fmt.Sprintf("Reader Stats: %#v", consumer.Stats()))
				for _, topicMapping := range topicMappings {
					if msg.Topic == topicMapping.Topic {
						go func(
							msg kafka.Message,
							topicMapping TopicMapping,
							providedServer *server.Server,
							logger *zerolog.Logger,
						) {
							err := topicMapping.Processor(
								msg.Value,
								topicMapping.ResultProducer,
								providedServer,
								logger,
							)
							if err != nil {
								logger.Error().Err(err).Msg("Processing failed.")
							}
						}(msg, topicMapping, providedServer, logger)
						if err := consumer.CommitMessages(ctx, msg); err != nil {
							logger.Error().Msg(fmt.Sprintf("Failed to commit: %s", err))
						}
					}
				}
			}

			// The below block will close the producer connection when the error threshold is reached.
			// @TODO: Test to determine if this Close() impacts the other goroutines that were passed
			// the same topicMappings before re-enabling this block.
			//for _, topicMapping := range topicMappings {
			//	logger.Trace().Msg(fmt.Sprintf("Closing producer connection %v", topicMapping))
			//	if err := topicMapping.ResultProducer.Close(); err != nil {
			//		logger.Error().Msg(fmt.Sprintf("Failed to close writer: %e", err))
			//	}
			//}
		}(topicMappings)
	}

	return nil
}

// NewConsumer returns a Kafka reader configured for the given topic and group.
func newConsumer(topics []string, groupId string, logger *zerolog.Logger) *kafka.Reader {
	brokers = strings.Split(os.Getenv("KAFKA_BROKERS"), ",")
	logger.Info().Msg(fmt.Sprintf("Subscribing to kafka topic %s on behalf of group %s using brokers %s", topics, groupId, brokers))
	kafkaLogger := logrus.New()
	kafkaLogger.SetLevel(logrus.WarnLevel)
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Dialer:         getDialer(logger),
		GroupTopics:    topics,
		GroupID:        groupId,
		StartOffset:    kafka.FirstOffset,
		Logger:         kafkaLogger,
		MaxWait:        time.Second * 20, // default 10s
		CommitInterval: time.Second,      // flush commits to Kafka every second
		MinBytes:       1e3,              // 1KB
		MaxBytes:       10e6,             // 10MB
	})
	logger.Trace().Msg(fmt.Sprintf("Reader create with subscription"))
	return reader
}

// Emit sends a message over the Kafka interface.
func Emit(producer *kafka.Writer, message []byte, logger *zerolog.Logger) error {
	logger.Info().Msg(fmt.Sprintf("Beginning data emission for topic %s", producer.Topic))

	messageKey := uuid.New()
	marshaledMessageKey, err := messageKey.MarshalBinary()
	if err != nil {
		logger.Error().Msg(fmt.Sprintf("Failed to marshal UUID into binary. Using default key value. %e", err))
		marshaledMessageKey = []byte("default")
	}

	err = producer.WriteMessages(
		context.Background(),
		kafka.Message{
			Value: []byte(message),
			Key:   []byte(marshaledMessageKey),
		},
	)
	if err != nil {
		logger.Error().Msg(fmt.Sprintf("Failed to write messages: %e", err))
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
