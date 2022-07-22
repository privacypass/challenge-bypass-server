package utils

import (
	"errors"
	"fmt"
	"time"

	awsDynamoTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
)

// ProcessingError is an error used for Kafka processing that communicates retry data for
// failures.
type ProcessingError struct {
	OriginalError  error
	FailureMessage string
	Temporary      bool
	Backoff        time.Duration
	KafkaMessage   kafka.Message
}

// Error makes ProcessingError an error
func (e ProcessingError) Error() string {
	msg := fmt.Sprintf("error: %s", e.FailureMessage)
	if e.OriginalError != nil {
		msg = fmt.Sprintf("%s: %s", msg, e.OriginalError)
	}
	return msg
}

// Cause implements Cause for error
func (e ProcessingError) Cause() error {
	return e.OriginalError
}

// ProcessingErrorFromErrorWithMessage converts an error into a ProcessingError
func ProcessingErrorFromErrorWithMessage(
	err error,
	message string,
	kafkaMessage kafka.Message,
	logger *zerolog.Logger,
) *ProcessingError {
	temporary, backoff := ErrorIsTemporary(err, logger)
	return &ProcessingError{
		OriginalError:  err,
		FailureMessage: message,
		Temporary:      temporary,
		Backoff:        backoff,
		KafkaMessage:   kafkaMessage,
	}
}

// ErrorIsTemporary takes an error and determines
func ErrorIsTemporary(err error, logger *zerolog.Logger) (bool, time.Duration) {
	var (
		dynamoProvisionedThroughput *awsDynamoTypes.ProvisionedThroughputExceededException
		dynamoRequestLimitExceeded  *awsDynamoTypes.RequestLimitExceeded
		dynamoInternalServerError   *awsDynamoTypes.InternalServerError
	)

	if errors.As(err, &dynamoProvisionedThroughput) {
		logger.Error().Err(err).Msg("Temporary message processing failure")
		return true, 1 * time.Minute
	}
	if errors.As(err, &dynamoRequestLimitExceeded) {
		logger.Error().Err(err).Msg("Temporary message processing failure")
		return true, 1 * time.Minute
	}
	if errors.As(err, &dynamoInternalServerError) {
		logger.Error().Err(err).Msg("Temporary message processing failure")
		return true, 1 * time.Minute
	}

	return false, 1 * time.Millisecond
}
