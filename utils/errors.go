package utils

import (
	"fmt"
	awsDynamoTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/rs/zerolog"
	"github.com/segmentio/kafka-go"
	"time"
)

type ProcessingError struct {
	Cause          error
	FailureMessage string
	Temporary      bool
	Backoff        time.Duration
	KafkaMessage   kafka.Message
}

// Error makes ProcessingError an error
func (e ProcessingError) Error() string {
	msg := fmt.Sprintf("error: %s", e.FailureMessage)
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %s", msg, e.Cause)
	}
	return msg
}

func ProcessingErrorFromErrorWithMessage(
	err error,
	message string,
	kafkaMessage kafka.Message,
	logger *zerolog.Logger,
) *ProcessingError {
	temporary, backoff := ErrorIsTemporary(err, logger)
	return &ProcessingError{
		Cause:          err,
		FailureMessage: message,
		Temporary:      temporary,
		Backoff:        backoff,
		KafkaMessage:   kafkaMessage,
	}
}

func ErrorIsTemporary(err error, logger *zerolog.Logger) (bool, time.Duration) {
	var ok bool
	err, ok = err.(*awsDynamoTypes.ProvisionedThroughputExceededException)
	if ok {
		logger.Error().Err(err).Msg("Temporary message processing failure")
		return true, 1 * time.Minute
	}
	err, ok = err.(*awsDynamoTypes.RequestLimitExceeded)
	if ok {
		logger.Error().Err(err).Msg("Temporary message processing failure")
		return true, 1 * time.Minute
	}
	err, ok = err.(*awsDynamoTypes.InternalServerError)
	if ok {
		logger.Error().Err(err).Msg("Temporary message processing failure")
		return true, 1 * time.Minute
	}

	return false, 1 * time.Millisecond
}
