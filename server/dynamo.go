package server

import (
	"errors"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	uuid "github.com/satori/go.uuid"
)

type Equivalence int64

const (
	UnknownEquivalence Equivalence = iota
	NoEquivalence
	IdEquivalence
	IdAndAllValueEquivalence
)

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
		c.Logger.Error("Redemption not found")
		return nil, errRedemptionNotFound
	}
	return &redemption, nil
}

func (c *Server) redeemTokenV2(issuer *Issuer, preimage *crypto.TokenPreimage, payload string, offset int64) error {
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
		Offset:    offset,
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

func (c *Server) PersistRedemption(redemption RedemptionV2) error {
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
			c.Logger.Error("Dynamo constraint violation")
			return err
		}
		c.Logger.Error("Error creating item")
		return err
	}
	return nil
}

// checkRedeemedTokenEquivalence returns whether just the ID of a given RedemptionV2 token
// matches an existing persisted record, the whole value matches, or neither match and
// this is a new token to be redeemed.
func (c *Server) CheckRedeemedTokenEquivalence(issuer *Issuer, preimage *crypto.TokenPreimage, payload string, offset int64) (*RedemptionV2, Equivalence, error) {
	preimageTxt, err := preimage.MarshalText()
	if err != nil {
		c.Logger.Error("Error Marshalling preimage")
		return nil, UnknownEquivalence, err
	}

	issuerUUID, err := uuid.FromString(issuer.ID)
	if err != nil {
		c.Logger.Error("Bad issuer id")
		return nil, UnknownEquivalence, errors.New("Bad issuer id")
	}
	id := uuid.NewV5(issuerUUID, string(preimageTxt))

	redemption := RedemptionV2{
		IssuerID:  issuer.ID,
		ID:        id.String(),
		PreImage:  string(preimageTxt),
		Payload:   payload,
		Timestamp: time.Now(),
		TTL:       issuer.ExpiresAt.Unix(),
		Offset:    offset,
	}

	existingRedemption, err := c.fetchRedemptionV2(id)

	// If err is nil that means that the record does exist in the database and we need
	// to determine whether the body is equivalent to what was provided or just the
	// id.
	if err == nil {
		if redemption == *existingRedemption {
			return &redemption, IdAndAllValueEquivalence, nil
		} else {
			return &redemption, IdEquivalence, nil
		}
	}
	return &redemption, NoEquivalence, nil
}
