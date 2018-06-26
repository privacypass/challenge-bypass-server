package server

import (
	b64 "encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/brave-intl/challenge-bypass-server/btd"
	"github.com/gorilla/mux"
)

type RegistrarResponse struct {
	Name string `json:"name"`
	G    string `json:"G"`
	H    string `json:"H"`
}

func (c *Server) registrarHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	json.NewEncoder(w).Encode(RegistrarResponse{vars["type"], b64.StdEncoding.EncodeToString(c.GBytes), b64.StdEncoding.EncodeToString(c.HBytes)})
}

func (c *Server) blindedTokenIssuerHandler(w http.ResponseWriter, r *http.Request) {
	var request btd.BlindTokenRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	marshaledTokenList, err := btd.ApproveTokens(request, c.SignKey, c.G, c.H)

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
	var request btd.BlindTokenRequest

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	err = btd.RedeemToken(request, []byte("somehost"), []byte("somepath"), c.RedeemKeys)
	if err != nil {
		http.Error(w, err.Error(), 400)
	}
}

func (c *Server) issuersHandlers(router *mux.Router) {
}
