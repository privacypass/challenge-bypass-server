package server

import (
	"encoding/json"
	"net/http"

	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/gorilla/mux"
)

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
		return
	}

	var id, payload string

	if err := c.redeemToken(issuerType, id, payload); err != nil {
		if err == DuplicateRedemptionError {
			http.Error(w, err.Error(), 400)
		} else {
			http.Error(w, err.Error(), 500)
		}
		return
	}
}

func (c *Server) blindedTokenRedemptionHandler(w http.ResponseWriter, r *http.Request) {}

func (c *Server) tokensHandlers(router *mux.Router) {
	router.HandleFunc("/v1/blindedToken/{type}/", c.blindedTokenIssuerHandler).Methods("POST")
	router.HandleFunc("/v1/blindedToken/{type}/{tokenId}/", c.blindedTokenRedeemHandler).Methods("POST")
	router.HandleFunc("/v1/blindedToken/{type}/{tokenId}/", c.blindedTokenRedemptionHandler).Methods("GET")
}
