package kafka

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	batgo_kafka "github.com/brave-intl/bat-go/utils/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	uuid "github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
)

var brokers []string

type Processor func(
	[]byte,
	*kafka.Writer,
	*server.Server,
	chan *ProcessingError,
	*zerolog.Logger,
) *ProcessingError

type ProcessingError struct {
	Cause     error
	Message   string
	Temporary bool
}

// Error makes ProcessingError an error
func (e ProcessingError) Error() string {
	msg := fmt.Sprintf("error: %s", e.Message)
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %s", msg, e.Cause)
	}
	return msg
}

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

	reader := newConsumer(topics, adsConsumerGroupV1, logger)
	if err != nil {
		return err
	}
	logger.Trace().Msg("Beginning message processing")
	for {
		logger.Trace().Msg(fmt.Sprintf("Fetching messages from Kafka"))
		var (
			wg      sync.WaitGroup
			results = make(chan *ProcessingError)
		)
		// Any error that occurs while getting the batch won't be available until
		// the Close() call.
		ctx := context.Background()
		batch, err := batchFromReader(ctx, reader, 20, logger)
		if err != nil {
			// This should be an app error that needs to communicate if its failure is
			// temporary or permanent. If temporary we need to handle it and if
			// permanent we need to commit and move on.
		}
	BatchProcessingLoop:
		for _, msg := range batch {
			wg.Add(1)
			if err != nil {
				// Indicates batch has no more messages. End the loop for
				// this batch and fetch another.
				if err == io.EOF {
					break BatchProcessingLoop
				}
			}
			logger.Info().Msg(fmt.Sprintf("Processing message for topic %s at offset %d", msg.Topic, msg.Offset))
			logger.Info().Msg(fmt.Sprintf("Reader Stats: %#v", reader.Stats()))
			// Check if any of the existing topicMappings match the fetched message
			for _, topicMapping := range topicMappings {
				if msg.Topic == topicMapping.Topic {
					go func(
						msg kafka.Message,
						topicMapping TopicMapping,
						providedServer *server.Server,
						logger *zerolog.Logger,
					) {
						defer wg.Done()
						err := topicMapping.Processor(
							msg.Value,
							topicMapping.ResultProducer,
							providedServer,
							results,
							logger,
						)
						if err != nil {
							logger.Error().Err(err).Msg("Processing failed.")
							results <- err
						}
					}(msg, topicMapping, providedServer, logger)
				}
			}
		}
	}

	return nil
}

// Pull messages out of the Reader's underlying batch so that they can be processed in parallel
// There is an ongoing discussion of batch message processing implementations with this
// library here: https://github.com/segmentio/kafka-go/issues/123
func batchFromReader(ctx context.Context, reader *kafka.Reader, count int, logger *zerolog.Logger) ([]kafka.Message, error) {
	var (
		messages []kafka.Message
		err      error
	)
	for i := 0; i < count; i++ {
		message, err := reader.FetchMessage(ctx)
		if err != nil {
			if err == io.EOF {
				logger.Trace().Msg("Batch complete")
			}
			continue
		}
		messages = append(messages, message)
	}
	return messages, err
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
	logger.Trace().Msg(fmt.Sprintf("Reader created with subscription"))
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
