package test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/brave-intl/challenge-bypass-server/utils/ptr"
)

// SetupDynamodbTables this function sets up tables for use in dynamodb tests.
func SetupDynamodbTables(db *dynamodb.DynamoDB) error {
	_, _ = db.DeleteTable(&dynamodb.DeleteTableInput{
		TableName: ptr.FromString("redemptions"),
	})

	input := &dynamodb.CreateTableInput{
		TableName:   ptr.FromString("redemptions"),
		BillingMode: ptr.FromString("PAY_PER_REQUEST"),
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("id"),
				AttributeType: aws.String("S"),
			},
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("id"),
				KeyType:       aws.String("HASH"),
			},
		},
	}

	_, err := db.CreateTable(input)
	if err != nil {
		return fmt.Errorf("error creating dynamodb table")
	}

	err = tableIsActive(db, *input.TableName, time.Second, 10*time.Millisecond)
	if err != nil {
		return fmt.Errorf("error table is not active %w", err)
	}

	return nil
}

func tableIsActive(db *dynamodb.DynamoDB, tableName string, timeout, duration time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return errors.New("timed out while waiting for table status to become ACTIVE")
		case <-time.After(duration):
			table, err := db.DescribeTable(&dynamodb.DescribeTableInput{
				TableName: aws.String(tableName),
			})
			if err != nil {
				return fmt.Errorf("instance.DescribeTable error %w", err)
			}
			if table.Table == nil || table.Table.TableStatus == nil || *table.Table.TableStatus != "ACTIVE" {
				continue
			}
			return nil
		}
	}
}
