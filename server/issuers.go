package server

import (
	b64 "encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/gorilla/mux"
)

type IssuerResponse struct {
	Name string `json:"name"`
	G    string `json:"G"`
	H    string `json:"H"`
}

type IssuerCreateRequest struct {
	Name      string `json:"name"`
	MaxTokens int    `json:"max_tokens"`
}

func (c *Server) getIssuer(issuerType string, w http.ResponseWriter) *Issuer {
	if issuer, err := c.fetchIssuer(issuerType); err != nil {
		if err == IssuerNotFoundError {
			http.Error(w, err.Error(), 400)
		} else {
			http.Error(w, err.Error(), 500)
		}
		return nil
	} else {
		return issuer
	}
}

func (c *Server) issuerHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuerType := vars["type"]
	issuer := c.getIssuer(issuerType, w)

	if issuer == nil {
		return
	}

	json.NewEncoder(w).Encode(IssuerResponse{issuer.IssuerType, b64.StdEncoding.EncodeToString(issuer.GBytes), b64.StdEncoding.EncodeToString(issuer.HBytes)})
}

func (c *Server) issuerCreateHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var req IssuerCreateRequest
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "Could not parse the request body", 400)
	}

	if err := c.createIssuer(req.Name, req.MaxTokens); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (c *Server) blindedTokenIssuerHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuerType := vars["type"]

	issuer := c.getIssuer(issuerType, w)

	if issuer == nil {
		return
	}

	var request btd.BlindTokenRequest

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	marshaledTokenList, err := btd.ApproveTokens(request, issuer.PrivateKey, issuer.G, issuer.H)

	if err != nil {
		http.Error(w, err.Error(), 400)
	}

	// EncodeByteArrays encodes the [][]byte as JSON
	jsonTokenList, err := btd.EncodeByteArrays(marshaledTokenList)
	if err != nil {
		http.Error(w, err.Error(), 400)
	}

	w.Write(jsonTokenList)
}

func (c *Server) blindedTokenRedeemHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuerType := vars["type"]

	issuer := c.getIssuer(issuerType, w)

	if issuer == nil {
		return
	}

	var request btd.BlindTokenRequest

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if err := btd.RedeemToken(request, []byte("somehost"), []byte("somepath"), [][]byte{issuer.PrivateKey}); err != nil {
		http.Error(w, err.Error(), 400)
	}
}

func (c *Server) issuersHandlers(router *mux.Router) {
	router.HandleFunc("/v1/issuers/{type}/", c.issuerHandler).Methods("GET")
	router.HandleFunc("/v1/issuers/", c.issuerCreateHandler).Methods("POST")
}
