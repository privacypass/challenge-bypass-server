package server

import (
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/brave-intl/bat-go/middleware"
	"github.com/brave-intl/bat-go/utils/closers"
	"github.com/brave-intl/bat-go/utils/handlers"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/go-chi/chi"
	"github.com/pressly/lg"
)

type issuerResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	PublicKey *crypto.PublicKey `json:"public_key"`
	ExpiresAt string            `json:"expires_at,omitempty"`
	Cohort    int               `json:"cohort"`
}

type issuerCreateRequest struct {
	Name      string     `json:"name"`
	Cohort    int        `json:"cohort"`
	MaxTokens int        `json:"max_tokens"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type issuerFetchRequestV2 struct {
	Cohort int `json:"cohort"`
}

func (c *Server) GetLatestIssuer(issuerType string, issuerCohort int) (*Issuer, *handlers.AppError) {
	issuer, err := c.fetchIssuersByCohort(issuerType, issuerCohort)
	if err != nil {
		if err == errIssuerCohortNotFound {
			c.Logger.Error("Issuer with given type and cohort not found")
			return nil, &handlers.AppError{
				Message: "Issuer with given type and cohort not found",
				Code:    404,
			}
		}
		c.Logger.Error("Error finding issuer")
		return nil, &handlers.AppError{
			Cause:   err,
			Message: "Error finding issuer",
			Code:    500,
		}
	}

	return &(*issuer)[0], nil
}

func (c *Server) GetIssuers(issuerType string) (*[]Issuer, error) {
	issuers, err := c.getIssuers(issuerType)
	if err != nil {
		c.Logger.Error(err)
		return nil, err
	}
	return issuers, nil
}
func (c *Server) getIssuers(issuerType string) (*[]Issuer, *handlers.AppError) {
	issuer, err := c.fetchIssuers(issuerType)
	if err != nil {
		if err == errIssuerNotFound {
			return nil, &handlers.AppError{
				Message: "Issuer not found",
				Code:    404,
			}
		}
		return nil, &handlers.AppError{
			Cause:   err,
			Message: "Error finding issuer",
			Code:    500,
		}
	}
	return issuer, nil
}

func (c *Server) issuerHandlerV1(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	defer closers.Panic(r.Body)

	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.GetLatestIssuer(issuerType, v1Cohort)
		if appErr != nil {
			return appErr
		}
		expiresAt := ""
		if !issuer.ExpiresAt.IsZero() {
			expiresAt = issuer.ExpiresAt.Format(time.RFC3339)
		}
		err := json.NewEncoder(w).Encode(issuerResponse{issuer.ID, issuer.IssuerType, issuer.SigningKey.PublicKey(), expiresAt, issuer.IssuerCohort})
		if err != nil {
			c.Logger.Error("Error encoding the issuer response")
			panic(err)
		}
		return nil
	}
	return nil
}

func (c *Server) issuerHandlerV2(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	defer closers.Panic(r.Body)

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req issuerFetchRequestV2
	if err := decoder.Decode(&req); err != nil {
		c.Logger.Error("Could not parse the request body")
		return handlers.WrapError(err, "Could not parse the request body", 400)
	}

	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.GetLatestIssuer(issuerType, req.Cohort)
		if appErr != nil {
			return appErr
		}
		expiresAt := ""
		if !issuer.ExpiresAt.IsZero() {
			expiresAt = issuer.ExpiresAt.Format(time.RFC3339)
		}
		err := json.NewEncoder(w).Encode(issuerResponse{issuer.ID, issuer.IssuerType, issuer.SigningKey.PublicKey(), expiresAt, issuer.IssuerCohort})
		if err != nil {
			c.Logger.Error("Error encoding the issuer response")
			panic(err)
		}
		return nil
	}
	return nil
}

func (c *Server) issuerGetAllHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	defer closers.Panic(r.Body)

	issuers, appErr := c.FetchAllIssuers()
	if appErr != nil {
		return &handlers.AppError{
			Cause:   appErr,
			Message: "Error getting issuers",
			Code:    500,
		}
	}
	respIssuers := []issuerResponse{}
	for _, issuer := range *issuers {
		expiresAt := ""
		if !issuer.ExpiresAt.IsZero() {
			expiresAt = issuer.ExpiresAt.Format(time.RFC3339)
		}
		respIssuers = append(respIssuers, issuerResponse{issuer.ID, issuer.IssuerType, issuer.SigningKey.PublicKey(), expiresAt, issuer.IssuerCohort})
	}

	err := json.NewEncoder(w).Encode(respIssuers)
	if err != nil {
		c.Logger.Error("Error encoding issuer")
		panic(err)
	}
	return nil
}

func (c *Server) issuerCreateHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	log := lg.Log(r.Context())

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req issuerCreateRequest
	if err := decoder.Decode(&req); err != nil {
		c.Logger.Error("Could not parse the request body")
		return handlers.WrapError(err, "Could not parse the request body", 400)
	}

	if req.ExpiresAt != nil {
		if req.ExpiresAt.Before(time.Now()) {
			c.Logger.Error("Expiration time has past")
			return &handlers.AppError{
				Message: "Expiration time has past",
				Code:    400,
			}
		}
	}

	// set the default cohort for v1 clients
	if req.Cohort == 0 {
		req.Cohort = v1Cohort
	}

	if err := c.createIssuer(req.Name, req.Cohort, req.MaxTokens, req.ExpiresAt); err != nil {
		log.Errorf("%s", err)
		return &handlers.AppError{
			Cause:   err,
			Message: "Could not create new issuer",
			Code:    500,
		}
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (c *Server) issuerRouterV1() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method("GET", "/{type}", middleware.InstrumentHandler("GetIssuer", handlers.AppHandler(c.issuerHandlerV1)))
	r.Method("POST", "/", middleware.InstrumentHandler("CreateIssuer", handlers.AppHandler(c.issuerCreateHandler)))
	r.Method("GET", "/", middleware.InstrumentHandler("GetAllIssuers", handlers.AppHandler(c.issuerGetAllHandler)))
	return r
}

func (c *Server) issuerRouterV2() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method("GET", "/{type}", middleware.InstrumentHandler("GetIssuer", handlers.AppHandler(c.issuerHandlerV2)))
	return r
}
