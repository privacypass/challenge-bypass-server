package server

import (
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr" // nolint
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/google/uuid"
)

// InitDynamo initialzes the dynamo database connection
func (c *Server) InitDynamo() {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	var config = &aws.Config{
		Region:   aws.String("us-west-2"),
		Endpoint: aws.String(c.dbConfig.DynamodbEndpoint),
	}

	if os.Getenv("ENV") != "production" {
		config.DisableSSL = aws.Bool(true)
	}

	svc := dynamodb.New(sess, config)
	c.dynamo = svc
}

// fetchRedemptionV2 takes a UUID v5 which is used to fetch and return a RedemptionV2 record
func (c *Server) fetchRedemptionV2(id uuid.UUID) (*RedemptionV2, error) {
	tableName := "redemptions"
	if os.Getenv("dynamodb_table") != "" {
		tableName = os.Getenv("dynamodb_table")
	}

	input := &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]*dynamodb.AttributeValue{
			"id": {
				S: aws.String(id.String()),
			},
		},
	}
	result, err := c.dynamo.GetItem(input)
	if err != nil {
		c.Logger.Error("Unable to get item")
		return nil, err
	}

	redemption := RedemptionV2{}

	err = dynamodbattribute.UnmarshalMap(result.Item, &redemption)
	if err != nil {
		c.Logger.Error("Unable to unmarshal redemption")
		panic(err)
	}

	if redemption.IssuerID == "" || redemption.ID == "" {
		return nil, errRedemptionNotFound
	}
	return &redemption, nil
}

func (c *Server) redeemTokenWithDynamo(issuer *Issuer, preimage *crypto.TokenPreimage, payload string) error {
	preimageTxt, err := preimage.MarshalText()
	if err != nil {
		c.Logger.Error("Error Marshalling preimage")
		return err
	}

	id := uuid.NewSHA1(*issuer.ID, []byte(string(preimageTxt)))

	redemption := RedemptionV2{
		IssuerID:  issuer.ID.String(),
		ID:        id.String(),
		PreImage:  string(preimageTxt),
		Payload:   payload,
		Timestamp: time.Now(),
		TTL:       issuer.ExpiresAt.Unix(),
	}

	av, err := dynamodbattribute.MarshalMap(redemption)
	if err != nil {
		c.Logger.Error("Error marshalling redemption")
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(id)"),
		TableName:           aws.String("redemptions"),
	}

	_, err = c.dynamo.PutItem(input)
	if err != nil {
		if err, ok := err.(awserr.Error); ok && err.Code() == "ConditionalCheckFailedException" { // unique constraint violation
			c.Logger.Error("Duplicate redemption")
			return errDuplicateRedemption
		}
		c.Logger.Error("Error creating item")
		return err
	}
	return nil
}
