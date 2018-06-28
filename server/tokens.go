package server

import (
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/gorilla/mux"
)

type BlindedTokenIssueRequest struct {
	Pretokens [][]byte `json:"pretokens"`
}

type BlindedTokenIssueResponse struct {
	BatchProof []byte   `json:"batchProof"`
	Tokens     [][]byte `json:"tokens"`
}

type BlindedTokenPair struct {
	T []byte `json:"t"`
	N []byte `json:"N"`
}

type BlindedTokenRedeemRequest struct {
	Token   BlindedTokenPair `json:"token"`
	Payload string           `json:"payload"`
}

func (c *Server) blindedTokenIssuerHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuerType := vars["type"]

	issuer := c.getIssuer(issuerType, w)

	if issuer == nil {
		return
	}

	var request BlindedTokenIssueRequest

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	marshaledTokenList, proof, err := btd.ApproveTokens(request.Pretokens, issuer.PrivateKey, issuer.G, issuer.H)

	if err != nil {
		http.Error(w, err.Error(), 500)
	}

	resp := BlindedTokenIssueResponse{proof, marshaledTokenList}

	jsonResponse, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), 500)
	}

	w.Write(jsonResponse)
}

func (c *Server) blindedTokenRedeemHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuerType := vars["type"]
	tokenId := vars["tokenId"]

	issuer := c.getIssuer(issuerType, w)

	if issuer == nil {
		return
	}

	var request BlindedTokenRedeemRequest

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	id := b64.StdEncoding.EncodeToString(request.Token.T)

	if tokenId != id {
		http.Error(w, fmt.Sprintf("tokenId %s does not match the POST input %s", tokenId, id), 400)
		return
	}

	if err := btd.RedeemToken([][]byte{request.Token.T, request.Token.N}, []byte(request.Payload), [][]byte{issuer.PrivateKey}); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if err := c.redeemToken(issuerType, id, request.Payload); err != nil {
		if err == DuplicateRedemptionError {
			http.Error(w, err.Error(), 400)
		} else {
			http.Error(w, err.Error(), 500)
		}
		return
	}
}

func (c *Server) blindedTokenRedemptionHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	issuerType := vars["type"]
	tokenId := vars["tokenId"]

	redemption, err := c.fetchRedemption(issuerType, tokenId)
	if err != nil {
		if err == RedemptionNotFoundError {
			http.Error(w, err.Error(), 400)
		} else {
			http.Error(w, err.Error(), 500)
		}

		return
	}

	jsonResponse, err := json.Marshal(redemption)
	if err != nil {
		http.Error(w, err.Error(), 500)
	}

	w.Write(jsonResponse)
}

func (c *Server) tokensHandlers(router *mux.Router) {
	router.HandleFunc("/v1/blindedToken/{type}/", c.blindedTokenIssuerHandler).Methods("POST")
	router.HandleFunc("/v1/blindedToken/{type}/{tokenId}/", c.blindedTokenRedeemHandler).Methods("POST")
	router.HandleFunc("/v1/blindedToken/{type}/{tokenId}/", c.blindedTokenRedemptionHandler).Methods("GET")
}
