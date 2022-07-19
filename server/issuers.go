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
	Cohort    int16             `json:"cohort"`
}

type issuerCreateRequest struct {
	Name      string     `json:"name"`
	Cohort    int16      `json:"cohort"`
	MaxTokens int        `json:"max_tokens"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type issuerV3CreateRequest struct {
	Name      string     `json:"name"`
	Cohort    int16      `json:"cohort"`
	MaxTokens int        `json:"max_tokens"`
	ExpiresAt *time.Time `json:"expires_at"`
	ValidFrom *time.Time `json:"valid_from"`
	Duration  string     `json:"duration"` // iso 8601 duration string
	Overlap   int        `json:"overlap"`  // how many extra buffer items to create
	Buffer    int        `json:"buffer"`   // number of signing keys to have in buffer
}

type issuerFetchRequestV2 struct {
	Cohort int16 `json:"cohort"`
}

func (c *Server) GetLatestIssuer(issuerType string, issuerCohort int16) (*Issuer, *handlers.AppError) {
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

func (c *Server) issuerGetHandlerV1(w http.ResponseWriter, r *http.Request) *handlers.AppError {
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

		var publicKey *crypto.PublicKey
		for _, k := range issuer.Keys {
			publicKey = k.SigningKey.PublicKey()
		}

		err := json.NewEncoder(w).Encode(issuerResponse{issuer.ID.String(), issuer.IssuerType, publicKey, expiresAt, issuer.IssuerCohort})
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

		// get the signing public key
		var publicKey *crypto.PublicKey
		for _, k := range issuer.Keys {
			publicKey = k.SigningKey.PublicKey()
		}

		err := json.NewEncoder(w).Encode(issuerResponse{issuer.ID.String(), issuer.IssuerType, publicKey, expiresAt, issuer.IssuerCohort})
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

		var publicKey *crypto.PublicKey
		for _, k := range issuer.Keys {
			publicKey = k.SigningKey.PublicKey()
		}

		respIssuers = append(respIssuers, issuerResponse{issuer.ID.String(), issuer.IssuerType, publicKey, expiresAt, issuer.IssuerCohort})
	}

	err := json.NewEncoder(w).Encode(respIssuers)
	if err != nil {
		c.Logger.Error("Error encoding issuer")
		panic(err)
	}
	return nil
}

// issuerV3CreateHandler - creation of a time aware issuer
func (c *Server) issuerV3CreateHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	log := lg.Log(r.Context())

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req issuerV3CreateRequest
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
	} else {
		// default ExpiresAt
		req.ExpiresAt = new(time.Time)
	}

	if err := c.createV3Issuer(Issuer{
		IssuerType:   req.Name,
		IssuerCohort: req.Cohort,
		MaxTokens:    req.MaxTokens,
		ExpiresAt:    *req.ExpiresAt,
		Buffer:       req.Buffer,
		Overlap:      req.Overlap,
		ValidFrom:    req.ValidFrom,
		Duration:     req.Duration,
	}); err != nil {
		log.Errorf("%s", err)
		return &handlers.AppError{
			Cause:   err,
			Message: "Could not create new issuer",
			Code:    500,
		}
	}

	w.WriteHeader(http.StatusCreated)
	return nil
}

func (c *Server) issuerCreateHandlerV2(w http.ResponseWriter, r *http.Request) *handlers.AppError {
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

	// set expires at if nil
	if req.ExpiresAt == nil {
		req.ExpiresAt = &time.Time{}
	}

	if err := c.createIssuerV2(req.Name, req.Cohort, req.MaxTokens, req.ExpiresAt); err != nil {
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

func (c *Server) issuerCreateHandlerV1(w http.ResponseWriter, r *http.Request) *handlers.AppError {
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

	// set expires at if nil
	if req.ExpiresAt == nil {
		req.ExpiresAt = &time.Time{}
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
	r.Method("GET", "/{type}", middleware.InstrumentHandler("GetIssuer", handlers.AppHandler(c.issuerGetHandlerV1)))
	r.Method("POST", "/", middleware.InstrumentHandler("CreateIssuer", handlers.AppHandler(c.issuerCreateHandlerV1)))
	r.Method("GET", "/", middleware.InstrumentHandler("GetAllIssuers", handlers.AppHandler(c.issuerGetAllHandler)))
	return r
}

func (c *Server) issuerRouterV2() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method("GET", "/{type}", middleware.InstrumentHandler("GetIssuerV2", handlers.AppHandler(c.issuerHandlerV2)))
	r.Method("POST", "/", middleware.InstrumentHandler("CreateIssuer", handlers.AppHandler(c.issuerCreateHandlerV2)))
	return r
}

func (c *Server) issuerRouterV3() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method("POST", "/", middleware.InstrumentHandler("CreateIssuerV3", handlers.AppHandler(c.issuerV3CreateHandler)))
	return r
}
