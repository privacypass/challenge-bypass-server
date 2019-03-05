package server

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/brave-intl/bat-go/middleware"
	"github.com/brave-intl/bat-go/utils/closers"
	"github.com/brave-intl/bat-go/utils/handlers"
	crypto "github.com/brave-intl/challenge-bypass-ristretto-ffi"
	"github.com/go-chi/chi"
	"github.com/pressly/lg"
)

type IssuerResponse struct {
	Name      string            `json:"name"`
	PublicKey *crypto.PublicKey `json:"public_key"`
}

type IssuerCreateRequest struct {
	Name      string `json:"name"`
	MaxTokens int    `json:"max_tokens"`
}

func (c *Server) getIssuer(issuerType string) (*Issuer, *handlers.AppError) {
	issuer, err := c.fetchIssuer(issuerType)
	if err != nil {
		if err == IssuerNotFoundError {
			return nil, &handlers.AppError{
				Message: "Issuer not found",
				Code:    404,
			}
		}
		return nil, &handlers.AppError{
			Error:   err,
			Message: "Error finding issuer",
			Code:    500,
		}
	}
	return issuer, nil
}

func (c *Server) issuerHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	defer closers.Panic(r.Body)

	if issuerType := chi.URLParam(r, "type"); issuerType != "" {
		issuer, appErr := c.getIssuer(issuerType)
		if appErr != nil {
			return appErr
		}

		err := json.NewEncoder(w).Encode(IssuerResponse{issuer.IssuerType, issuer.SigningKey.PublicKey()})
		if err != nil {
			panic(err)
		}
		return nil
	}
	return nil
}

func (c *Server) issuerCreateHandler(w http.ResponseWriter, r *http.Request) *handlers.AppError {
	log := lg.Log(r.Context())

	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestSize))
	var req IssuerCreateRequest
	if err := decoder.Decode(&req); err != nil {
		return handlers.WrapError("Could not parse the request body", err)
	}

	if err := c.createIssuer(req.Name, req.MaxTokens); err != nil {
		log.Errorf("%s", err)
		return &handlers.AppError{
			Error:   err,
			Message: "Could not create new issuer",
			Code:    500,
		}
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

func (c *Server) issuerRouter() chi.Router {
	r := chi.NewRouter()
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.SimpleTokenAuthorizedOnly)
	}
	r.Method("GET", "/{type}", middleware.InstrumentHandler("GetIssuer", handlers.AppHandler(c.issuerHandler)))
	r.Method("POST", "/", middleware.InstrumentHandler("CreateIssuer", handlers.AppHandler(c.issuerCreateHandler)))
	return r
}
