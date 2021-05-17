package server

import (
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	uuid "github.com/satori/go.uuid"
)

func (c *Server) initDynamo() {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := dynamodb.New(sess, &aws.Config{
		Region:                        aws.String("us-west-2"),
		Endpoint:                      aws.String(c.dbConfig.DynamodbEndpoint),
		CredentialsChainVerboseErrors: aws.Bool(true),
	})

	c.dynamo = svc
}

func (c *Server) fetchRedemptionV2(issuer *Issuer, ID string) (*RedemptionV2, error) {
	issuerUUID, err := uuid.FromString(issuer.ID)
	if err != nil {
		c.Logger.Error("Bad issuer id")
		return nil, errors.New("Bad issuer id")
	}

	id := uuid.NewV5(issuerUUID, ID)

	input := &dynamodb.GetItemInput{
		TableName: aws.String("redemptions"),
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
		c.Logger.Error("Redemption not found")
		return nil, errRedemptionNotFound
	}
	return &redemption, nil
}

func (c *Server) redeemTokenV2(issuer *Issuer, preimage *crypto.TokenPreimage, payload string) error {
	preimageTxt, err := preimage.MarshalText()
	if err != nil {
		c.Logger.Error("Error Marshalling preimage")
		return err
	}

	issuerUUID, err := uuid.FromString(issuer.ID)
	if err != nil {
		c.Logger.Error("Bad issuer id")
		return errors.New("Bad issuer id")
	}

	id := uuid.NewV5(issuerUUID, string(preimageTxt))

	redemption := RedemptionV2{
		IssuerID:  issuer.ID,
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
