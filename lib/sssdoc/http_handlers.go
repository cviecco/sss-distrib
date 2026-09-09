package sssdoc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"filippo.io/age"
)

const jsonResponseContentType = "application/json; charset=utf-8"

type SssShareStatus struct {
	Processed int `json:"processed"`
	Required  int `json:"required"`
}

func (doc *SssProcessor) GetShareStatusHandler(w http.ResponseWriter, r *http.Request) {
	if doc.Doc == nil {
		http.Error(w, "internal service error", http.StatusInternalServerError)
		return
	}
	payload, err := json.Marshal(SssShareStatus{
		Processed: len(doc.processedShare),
		Required:  doc.Doc.RequiredShares,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", jsonResponseContentType)
	if _, err := w.Write(payload); err != nil {
		// The client connection may have been closed; nothing else to do.
		return
	}
}

type SssKexchangeKeys struct {
	AgePubKeys []string `json:"age_pub_keys"`
}

func (doc *SssProcessor) GetKeyExchangePublicKeysHandler(w http.ResponseWriter, r *http.Request) {
	pubAgeString := doc.agePQKey.Recipient().String()
	payload, err := json.Marshal(SssKexchangeKeys{
		AgePubKeys: []string{pubAgeString},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if _, err := w.Write(payload); err != nil {
		// The client connection may have been closed; nothing else to do.
		return
	}
}

type processEncrypedShareParams struct {
	EncrypedShare []byte
}

func (doc *SssProcessor) ProcessEncryptedShareFromParams(params processEncrypedShareParams) (usererr error, internalerr error) {
	//decrpt the share
	agePQrecipient := doc.agePQKey
	idReader := bytes.NewReader([]byte(agePQrecipient.String()))
	identity, err := age.ParseIdentities(idReader)
	if err != nil {
		// TODO, dont do the +%v
		return nil, fmt.Errorf("unable to decrypt parse identities fail  %w", err)
	}
	encReader := bytes.NewReader(params.EncrypedShare)
	plaintextReader, err := age.Decrypt(encReader, identity...)
	if err != nil {
		// TODO, dont do the +%v
		return fmt.Errorf("unable to decrypt  %w", err), nil
	}
	plaintextShare, err := io.ReadAll(plaintextReader)
	if err != nil {
		// TODO, dont do the +%v
		return nil, fmt.Errorf("unable to readdecrypted bytes  %w", err)
	}
	_, err = doc.ProcessShare(plaintextShare)
	return nil, err
}

func (sp *SssProcessor) ParseEncryptedShareFromParams(w http.ResponseWriter, r *http.Request) (*processEncrypedShareParams, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, err
	}
	//fmt.Printf("parsing r==%+v", r)
	b64EncShare := r.FormValue("b64encShare")
	if b64EncShare == "" {
		return nil, fmt.Errorf("Missing required value  'b64encShare'")
	}

	var rvalue processEncrypedShareParams
	rvalue.EncrypedShare, err = base64.URLEncoding.DecodeString(b64EncShare)
	if err != nil {
		return nil, fmt.Errorf("String is not b64 URL encoded %w", err)
	}
	return &rvalue, nil
}

// Keys should always be passed encrypted
func (sp *SssProcessor) ProcessKeyShareHandler(w http.ResponseWriter, r *http.Request) {
	/// wrap in limited reader?
	params, err := sp.ParseEncryptedShareFromParams(w, r)
	if err != nil {
		http.Error(w, fmt.Sprintf("Bad/Invalid params: %s ", err), http.StatusBadRequest)
		return
	}
	userErr, err := sp.ProcessEncryptedShareFromParams(*params)
	if userErr != nil {
		http.Error(w, fmt.Sprintf("Bad/Invalid params: %s ", err), http.StatusBadRequest)
		return
	}
	if err != nil {
		fmt.Printf("internal err=%s", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	//On success we just return the status doc
	sp.GetShareStatusHandler(w, r)
}
