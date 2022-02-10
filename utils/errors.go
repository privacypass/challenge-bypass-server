package utils

import (
	"fmt"
	awsDynamoTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/segmentio/kafka-go"
)

type ProcessingError struct {
	Cause          error
	FailureMessage string
	Temporary      bool
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

func ErrorIsTemporary(err error) bool {
	var ok bool
	err, ok = err.(*awsDynamoTypes.ProvisionedThroughputExceededException)
	if !ok {
		return true
	}
	err, ok = err.(*awsDynamoTypes.RequestLimitExceeded)
	if !ok {
		return true
	}
	err, ok = err.(*awsDynamoTypes.InternalServerError)
	if !ok {
		return true
	}

	return false
}
