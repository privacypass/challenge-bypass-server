package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/brave-intl/bat-go/middleware"
	"github.com/brave-intl/bat-go/utils/handlers"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/go-chi/chi"
	uuid "github.com/satori/go.uuid"
)

const (
	v1Cohort = int16(1)
)

type blindedTokenIssueRequest struct {
	BlindedTokens []*crypto.BlindedToken `json:"blinded_tokens"`
}

type BlindedTokenIssueRequestV2 struct {
	BlindedTokens []*crypto.BlindedToken `json:"blinded_tokens"`
	IssuerCohort  int16                  `json:"cohort"`
}

type blindedTokenIssueResponse struct {
	BatchProof   *crypto.BatchDLEQProof `json:"batch_proof"`
	SignedTokens []*crypto.SignedToken  `json:"signed_tokens"`
	PublicKey    *crypto.PublicKey      `json:"public_key"`
}

type blindedTokenRedeemRequest struct {
	Payload       string                        `json:"payload"`
	TokenPreimage *crypto.TokenPreimage         `json:"t"`
	Signature     *crypto.VerificationSignature `json:"signature"`
}

type blindedTokenRedeemResponse struct {
	Cohort int16 `json:"cohort"`
}

type BlindedTokenRedemptionInfo struct {
	TokenPreimage *crypto.TokenPreimage         `json:"t"`
	Signature     *crypto.VerificationSignature `json:"signature"`
	Issuer        string                        `json:"issuer"`
}

type BlindedTokenBulkRedeemRequest struct {
	Payload string                       `json:"payload"`
	Tokens  []BlindedTokenRedemptionInfo `json:"tokens"`
}

func (c *Server) BlindedTokenIssuerHandlerV2(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	var response blindedTokenIssueResponse
	if issuerType := chi.URLParam(r, "type"); issuerType != "" {

		var request BlindedTokenIssueRequestV2

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			c.Logger.WithError(err)
			return handlers.WrapError(err, "Could not parse the request body", 400)
		}

		if request.BlindedTokens == nil {
			c.Logger.Debug("Empty request")
			return &handlers.AppError{
				Message: "Empty request",
				Code:    http.StatusBadRequest,
			}
		}

		if request.IssuerCohort != 0 && request.IssuerCohort != 1 {
			c.Logger.Debug("Not supported Cohort")
			return &handlers.AppError{
				Message: "Not supported Cohort",
				Code:    http.StatusBadRequest,
			}
		}

		issuer, appErr := c.GetLatestIssuer(issuerType, request.IssuerCohort)
		if appErr != nil {
			return appErr
		}

		// get latest signing key from issuer
		var signingKey *crypto.SigningKey
		if len(issuer.Keys) > 0 {
			signingKey = issuer.Keys[len(issuer.Keys)-1].SigningKey
		} else {
			// need to have atleast one signing key
			c.Logger.Errorf("Invalid issuer, must have one signing key: %s", issuer.IssuerType)
			return &handlers.AppError{
				Message: "Invalid Issuer",
				Code:    http.StatusBadRequest,
			}
		}

		signedTokens, proof, err := btd.ApproveTokens(request.BlindedTokens, signingKey)
		if err != nil {
			c.Logger.Debug("Could not approve new tokens")
			return &handlers.AppError{
				Cause:   err,
				Message: "Could not approve new tokens",
				Code:    http.StatusInternalServerError,
			}
		}
		response = blindedTokenIssueResponse{proof, signedTokens, signingKey.PublicKey()}
	}
	return handlers.RenderContent(r.Context(), response, w, http.StatusOK)
}

// Old endpoint, that always handles tokens with v1cohort
func (c *Server) blindedTokenIssuerHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	var response blindedTokenIssueResponse
	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.GetLatestIssuer(issuerType, v1Cohort)
		if appErr != nil {
			return appErr
		}

		var request blindedTokenIssueRequest

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			c.Logger.Debug("Could not parse the request body")
			return handlers.WrapError(err, "Could not parse the request body", 400)
		}

		if request.BlindedTokens == nil {
			c.Logger.Debug("Empty request")
			return &handlers.AppError{
				Message: "Empty request",
				Code:    http.StatusBadRequest,
			}
		}

		// get latest signing key from issuer
		var signingKey *crypto.SigningKey
		if len(issuer.Keys) > 0 {
			signingKey = issuer.Keys[len(issuer.Keys)-1].SigningKey
		} else {
			// need to have atleast one signing key
			c.Logger.Errorf("Invalid issuer, must have one signing key: %s", issuer.IssuerType)
			return &handlers.AppError{
				Message: "Invalid Issuer",
				Code:    http.StatusBadRequest,
			}
		}

		signedTokens, proof, err := btd.ApproveTokens(request.BlindedTokens, signingKey)
		if err != nil {
			c.Logger.Debug("Could not approve new tokens")
			return &handlers.AppError{
				Cause:   err,
				Message: "Could not approve new tokens",
				Code:    http.StatusInternalServerError,
			}
		}
		response = blindedTokenIssueResponse{proof, signedTokens, signingKey.PublicKey()}
	}
	return handlers.RenderContent(r.Context(), response, w, http.StatusOK)
}

func (c *Server) blindedTokenRedeemHandlerV3(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	var response blindedTokenRedeemResponse
	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuers, appErr := c.getIssuers(issuerType)
		if appErr != nil {
			return appErr
		}

		var request blindedTokenRedeemRequest

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			c.Logger.Debug("Could not parse the request body")
			return handlers.WrapError(err, "Could not parse the request body", 400)
		}

		if request.TokenPreimage == nil || request.Signature == nil {
			c.Logger.Debug("Empty request")
			return &handlers.AppError{
				Message: "Empty request",
				Code:    http.StatusBadRequest,
			}
		}

		var verified = false
		var verifiedIssuer = &Issuer{}
		var verifiedCohort = int16(0)
		for _, issuer := range *issuers {
			if !issuer.ExpiresAt.IsZero() && issuer.ExpiresAt.Before(time.Now()) {
				continue
			}

			// validate issuer is a v3 issuer
			if issuer.Version != 3 {
				return &handlers.AppError{
					Message: "Invalid Issuer",
					Code:    http.StatusBadRequest,
				}
			}

			// iterate through the keys until we have one that is valid
			var signingKey *crypto.SigningKey
			for _, k := range issuer.Keys {
				if k.StartAt == nil || k.EndAt == nil {
					return &handlers.AppError{
						Message: "Issuer has invalid keys for v3",
						Code:    http.StatusBadRequest,
					}
				}

				if k.StartAt.Before(time.Now()) && k.EndAt.After(time.Now()) {
					signingKey = k.SigningKey
					break
				}
			}
			if signingKey == nil {
				return &handlers.AppError{
					Message: "Issuer has no key that corresponds to start < now < end",
					Code:    http.StatusBadRequest,
				}
			}

			if err := btd.VerifyTokenRedemption(request.TokenPreimage, request.Signature, request.Payload, []*crypto.SigningKey{signingKey}); err != nil {
				verified = false
			} else {
				verified = true
				verifiedIssuer = &issuer
				verifiedCohort = issuer.IssuerCohort
				break
			}
		}

		if !verified {
			c.Logger.Debug("Could not verify that the token redemption is valid")
			return &handlers.AppError{
				Message: "Could not verify that token redemption is valid",
				Code:    http.StatusBadRequest,
			}
		}

		if err := c.RedeemToken(verifiedIssuer, request.TokenPreimage, request.Payload); err != nil {
			if errors.Is(err, errDuplicateRedemption) {
				return &handlers.AppError{
					Message: err.Error(),
					Code:    http.StatusConflict,
				}
			}
			return &handlers.AppError{
				Cause:   err,
				Message: "Could not mark token redemption",
				Code:    http.StatusInternalServerError,
			}

		}
		response = blindedTokenRedeemResponse{verifiedCohort}
	}
	return handlers.RenderContent(r.Context(), response, w, http.StatusOK)
}

func (c *Server) blindedTokenRedeemHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	var response blindedTokenRedeemResponse
	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuers, appErr := c.getIssuers(issuerType)
		if appErr != nil {
			return appErr
		}

		var request blindedTokenRedeemRequest

		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
			c.Logger.Debug("Could not parse the request body")
			return handlers.WrapError(err, "Could not parse the request body", 400)
		}

		if request.TokenPreimage == nil || request.Signature == nil {
			c.Logger.Error("Empty request")
			return &handlers.AppError{
				Message: "Empty request",
				Code:    http.StatusBadRequest,
			}
		}

		var verified = false
		var verifiedIssuer = &Issuer{}
		var verifiedCohort = int16(0)
		for _, issuer := range *issuers {
			if !issuer.ExpiresAt.IsZero() && issuer.ExpiresAt.Before(time.Now()) {
				continue
			}

			// get latest signing key from issuer
			var signingKey *crypto.SigningKey
			if len(issuer.Keys) > 0 {
				signingKey = issuer.Keys[len(issuer.Keys)-1].SigningKey
			} else {
				// need to have atleast one signing key
				c.Logger.Errorf("Invalid issuer, must have one signing key: %s", issuer.IssuerType)
				return &handlers.AppError{
					Message: "Invalid Issuer",
					Code:    http.StatusBadRequest,
				}
			}

			if err := btd.VerifyTokenRedemption(request.TokenPreimage, request.Signature, request.Payload, []*crypto.SigningKey{signingKey}); err != nil {
				verified = false
			} else {
				verified = true
				verifiedIssuer = &issuer
				verifiedCohort = issuer.IssuerCohort
				break
			}
		}

		if !verified {
			c.Logger.Error("Could not verify that the token redemption is valid")
			return &handlers.AppError{
				Message: "Could not verify that token redemption is valid",
				Code:    http.StatusBadRequest,
			}
		}

		if err := c.RedeemToken(verifiedIssuer, request.TokenPreimage, request.Payload); err != nil {
			if errors.Is(err, errDuplicateRedemption) {
				return &handlers.AppError{
					Message: err.Error(),
					Code:    http.StatusConflict,
				}
			}
			return &handlers.AppError{
				Cause:   err,
				Message: "Could not mark token redemption",
				Code:    http.StatusInternalServerError,
			}
		}
		response = blindedTokenRedeemResponse{verifiedCohort}
	}
	return handlers.RenderContent(r.Context(), response, w, http.StatusOK)
}

func (c *Server) blindedTokenBulkRedeemHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	var request BlindedTokenBulkRedeemRequest

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize)).Decode(&request); err != nil {
		c.Logger.Debug("Could not parse the request body")
		return handlers.WrapError(err, "Could not parse the request body", 400)
	}

	tx, err := c.db.Begin()
	if err != nil {
		c.Logger.Debug("Could not start bulk token redemption db transaction")
		return handlers.WrapError(err, "Could not start bulk token redemption db transaction", 400)
	}

	for _, token := range request.Tokens {
		// @TODO: this code seems to be from an old version - we use the `redeemTokenWithDB`, and we have no tests, so I
		// assume that is no longer used, hence the usage of v1Cohort.
		issuer, appErr := c.GetLatestIssuer(token.Issuer, v1Cohort)

		if appErr != nil {
			_ = tx.Rollback()
			c.Logger.Error(appErr.Error())
			return appErr
		}

		if token.TokenPreimage == nil || token.Signature == nil {
			_ = tx.Rollback()
			return &handlers.AppError{
				Message: "Missing preimage or signature",
				Code:    http.StatusBadRequest,
			}
		}

		// get latest signing key from issuer
		var signingKey *crypto.SigningKey
		if len(issuer.Keys) > 0 {
			signingKey = issuer.Keys[len(issuer.Keys)-1].SigningKey
		} else {
			// need to have atleast one signing key
			c.Logger.Errorf("Invalid issuer, must have one signing key: %s", issuer.IssuerType)
			return &handlers.AppError{
				Message: "Invalid Issuer",
				Code:    http.StatusBadRequest,
			}
		}

		err := btd.VerifyTokenRedemption(token.TokenPreimage, token.Signature, request.Payload, []*crypto.SigningKey{signingKey})
		if err != nil {
			c.Logger.Error(err.Error())
			_ = tx.Rollback()
			return handlers.WrapError(err, "Could not verify that token redemption is valid", 400)
		}

		if err := redeemTokenWithDB(tx, token.Issuer, token.TokenPreimage, request.Payload); err != nil {
			c.Logger.Error(err.Error())
			_ = tx.Rollback()
			if err == errDuplicateRedemption {
				return &handlers.AppError{
					Message: err.Error(),
					Code:    http.StatusConflict,
				}
			} else {
				return &handlers.AppError{
					Cause:   err,
					Message: "Could not mark token redemption",
					Code:    http.StatusInternalServerError,
				}
			}
		}

	}
	err = tx.Commit()
	if err != nil {
		c.Logger.Error(err.Error())
		return &handlers.AppError{
			Cause:   err,
			Message: "Could not mark token redemption",
			Code:    http.StatusInternalServerError,
		}
	}

	return handlers.RenderContent(r.Context(), nil, w, http.StatusOK)
}

func (c *Server) blindedTokenRedemptionHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	var response interface{}
	if issuerID := chi.URLParam(r, "id"); issuerID != "" {
		tokenID := chi.URLParam(r, "tokenId")
		if tokenID == "" {
			return &handlers.AppError{
				Message: errRedemptionNotFound.Error(),
				Code:    http.StatusBadRequest,
			}
		}

		tokenID, err := url.PathUnescape(tokenID)
		if err != nil {
			c.Logger.Debug("Bad request - incorrect token ID")
			return &handlers.AppError{
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			}
		}

		issuer, err := c.fetchIssuer(issuerID)
		if err != nil {
			c.Logger.Debug("Bad request - incorrect issuer ID")
			return &handlers.AppError{
				Message: err.Error(),
				Code:    http.StatusBadRequest,
			}
		}

		if issuer.Version == 2 {
			issuerUUID, err := uuid.FromString(issuer.ID)
			if err != nil {
				c.Logger.Debug("Bad issuer id")
				return &handlers.AppError{
					Message: fmt.Sprintf("Bad issuer id: %s", err.Error()),
					Code:    http.StatusBadRequest,
				}
			}
			redemption, err := c.fetchRedemptionV2(uuid.NewV5(issuerUUID, tokenID))
			if err != nil {
				if err == errRedemptionNotFound {
					c.Logger.Debug("Redemption not found")
					return &handlers.AppError{
						Message: err.Error(),
						Code:    http.StatusBadRequest,
					}
				}
				return &handlers.AppError{
					Cause:   err,
					Message: "Could not check token redemption",
					Code:    http.StatusInternalServerError,
				}
			}
			return handlers.RenderContent(r.Context(), redemption, w, http.StatusOK)
		}

		redemption, err := c.fetchRedemption(issuer.IssuerType, tokenID)
		if err != nil {
			if err == errRedemptionNotFound {
				return &handlers.AppError{
					Message: err.Error(),
					Code:    http.StatusBadRequest,
				}
			}
			return &handlers.AppError{
				Cause:   err,
				Message: "Could not check token redemption",
				Code:    http.StatusInternalServerError,
			}
		}
		response = redemption
	}
	return handlers.RenderContent(r.Context(), response, w, http.StatusOK)
}

func (c *Server) tokenRouterV1() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method(http.MethodPost, "/{type}", middleware.InstrumentHandler("IssueTokens", handlers.AppHandler(c.blindedTokenIssuerHandler)))
	r.Method(http.MethodPost, "/{type}/redemption/", middleware.InstrumentHandler("RedeemTokens", handlers.AppHandler(c.blindedTokenRedeemHandler)))
	r.Method(http.MethodGet, "/{id}/redemption/{tokenId}", middleware.InstrumentHandler("CheckToken", handlers.AppHandler(c.blindedTokenRedemptionHandler)))
	r.Method(http.MethodPost, "/bulk/redemption/", middleware.InstrumentHandler("BulkRedeemTokens", handlers.AppHandler(c.blindedTokenBulkRedeemHandler)))
	return r
}

// New end point to generated marked tokens
func (c *Server) tokenRouterV2() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method(http.MethodPost, "/{type}", middleware.InstrumentHandler("IssueTokens", handlers.AppHandler(c.BlindedTokenIssuerHandlerV2)))
	return r
}

// New end point to generated marked tokens
func (c *Server) tokenRouterV3() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	// for redeeming time aware issued tokens
	r.Method(http.MethodPost, "/{type}/redemption/", middleware.InstrumentHandler("RedeemTokens", handlers.AppHandler(c.blindedTokenRedeemHandlerV3)))
	return r
}
