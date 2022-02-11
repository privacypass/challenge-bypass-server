package kafka

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	batgo_kafka "github.com/brave-intl/bat-go/utils/kafka"
	"github.com/brave-intl/challenge-bypass-server/server"
	"github.com/brave-intl/challenge-bypass-server/utils"
	uuid "github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
	"github.com/sirupsen/logrus"
)

var brokers []string

type Processor func(
	kafka.Message,
	*kafka.Writer,
	[]server.Equivalence,
	*server.Server,
	chan *utils.ProcessingError,
	*zerolog.Logger,
) *utils.ProcessingError

type TopicMapping struct {
	Topic                string
	ResultProducer       *kafka.Writer
	Processor            Processor
	Group                string
	TolerableEquivalence []server.Equivalence
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
			// Either the record does not exist and there is NoEquivalence,
			// or this is a retry of a previous record including a matching
			// offset.
			TolerableEquivalence: []server.Equivalence{server.NoEquivalence, server.IdAndAllValueEquivalence},
		},
		TopicMapping{
			Topic: adsRequestSignV1Topic,
			ResultProducer: kafka.NewWriter(kafka.WriterConfig{
				Brokers: brokers,
				Topic:   adsResultSignV1Topic,
				Dialer:  getDialer(logger),
			}),
			Processor:            SignedBlindedTokenIssuerHandler,
			Group:                adsConsumerGroupV1,
			TolerableEquivalence: []server.Equivalence{},
		},
	}
	var topics []string
	for _, topicMapping := range topicMappings {
		topics = append(topics, topicMapping.Topic)
	}

	reader := newConsumer(topics, adsConsumerGroupV1, logger)

	// `kafka-go` exposes messages one at a time through its normal interfaces despite
	// collecting messages with batching from Kafka. To process these messages in
	// parallel we use the `FetchMessage` method in a loop to collect a set of messages
	// for processing. Successes and permanent failures are committed and temporary
	// failures are not committed and are retried. Miscategorization of errors can
	// cause the consumer to become stuck forever, so it's important that permanent
	// failures are not categorized as temporary.
	for {
		var (
			wg      sync.WaitGroup
			results = make(chan *utils.ProcessingError)
		)
		// Any error that occurs while getting the batch won't be available until
		// the Close() call.
		ctx := context.Background()
		batch, err := batchFromReader(ctx, reader, 20, logger)
		if err != nil {
			logger.Error().Err(err).Msg("Batching failed")
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
					logger.Info().Msg("Batch complete. Ending loop.")
					break BatchProcessingLoop
				}
			}
			logger.Info().Msg(fmt.Sprintf("Processing message for topic %s at offset %d", msg.Topic, msg.Offset))
			logger.Info().Msg(fmt.Sprintf("Reader Stats: %#v", reader.Stats()))
			wgDoneDeferred := false
			// Check if any of the existing topicMappings match the fetched message
			for _, topicMapping := range topicMappings {
				if msg.Topic == topicMapping.Topic {
					wgDoneDeferred = true
					go func(
						msg kafka.Message,
						topicMapping TopicMapping,
						providedServer *server.Server,
						logger *zerolog.Logger,
					) {
						defer wg.Done()
						err := topicMapping.Processor(
							msg,
							topicMapping.ResultProducer,
							topicMapping.TolerableEquivalence,
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
			// If the topic in the message doesn't match andy of the topicMappings
			// then the goroutine will not be spawned and wg.Done() won't be
			// called. If this happens, be sure to call it.
			if !wgDoneDeferred {
				wg.Done()
			}
		}
		close(results)
		// Iterate over any failures and get the earliest temporary failure offset
		var temporaryErrors []*utils.ProcessingError
		for processingError := range results {
			if processingError.Temporary {
				continue
			} else {
				temporaryErrors = append(temporaryErrors, processingError)
			}
		}
		// If there are temporary errors, sort them so that the first item in the
		// has the lowest offset. Only run sort if there is more than one temporary
		// error.
		if len(temporaryErrors) > 0 {
			logger.Error().Msg(fmt.Sprintf("Temporary errors: %#v", temporaryErrors))
			if len(temporaryErrors) > 1 {
				sort.Slice(temporaryErrors, func(i, j int) bool {
					return temporaryErrors[i].KafkaMessage.Offset < temporaryErrors[j].KafkaMessage.Offset
				})
			}
			// Iterate over the batch to find the message that came before the first
			// temporary failure and commit it. This will ensure that the temporary
			// failure is picked up as the first item in the next batch.
			for _, message := range batch {
				if message.Offset == temporaryErrors[0].KafkaMessage.Offset-1 {
					if err := reader.CommitMessages(ctx, message); err != nil {
						logger.Error().Msg(fmt.Sprintf("Failed to commit: %s", err))
					}
					time.Sleep(temporaryErrors[0].Backoff)
				}
			}
		} else if len(batch) > 0 {
			sort.Slice(batch, func(i, j int) bool {
				return batch[i].Offset < batch[j].Offset
			})
			logger.Info().Msg(fmt.Sprintf("Committing offset", batch[0].Offset))
			if err := reader.CommitMessages(ctx, batch[0]); err != nil {
				logger.Error().Err(err).Msg("Failed to commit")
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
		innerctx, _ := context.WithTimeout(ctx, 100*time.Millisecond)
		message, err := reader.FetchMessage(innerctx)
		if err != nil {
			if err == io.EOF {
				logger.Info().Msg("Batch complete")
			} else if err.Error() != "context deadline exceeded" {
				logger.Error().Err(err).Msg("Batch item error")
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
	dialer := getDialer(logger)
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Dialer:         dialer,
		GroupTopics:    topics,
		GroupID:        groupId,
		StartOffset:    kafka.FirstOffset,
		Logger:         kafkaLogger,
		MaxWait:        time.Second * 20, // default 20s
		CommitInterval: time.Second,      // flush commits to Kafka every second
		MinBytes:       1e3,              // 1KB
		MaxBytes:       10e6,             // 10MB
	})
	logger.Info().Msg(fmt.Sprintf("Reader created with subscription"))
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
	if os.Getenv("ENV") != "local" {
		logger.Info().Msg("Generating TLSDialer")
		tlsDialer, _, err := batgo_kafka.TLSDialer()
		dialer = tlsDialer
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("Failed to initialize TLS dialer: %e", err))
		}
	} else {
		logger.Info().Msg("Generating Dialer")
		dialer = &kafka.Dialer{
			Timeout:   10 * time.Second,
			DualStack: true,
		}
	}
	return dialer
}
