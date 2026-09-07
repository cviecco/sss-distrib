package sssdoc

import (
	"bytes"
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

func (doc *SssDoc) GetShareStatusHandler(w http.ResponseWriter, r *http.Request) {
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

func (doc *SssDoc) GetKeyExchangePublicKeysHandler(w http.ResponseWriter, r *http.Request) {
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

func (doc *SssDoc) ProcessEncryptedShareFromParams(params processEncrypedShareParams) error {
	//decrpt the share
	agePQrecipient := doc.agePQKey.Recipient()
	idReader := bytes.NewReader([]byte(agePQrecipient.String()))
	identity, err := age.ParseIdentities(idReader)
	if err != nil {
		// TODO, dont do the +%v
		return fmt.Errorf("unable to decrypt  %w", err)
	}
	encReader := bytes.NewReader(params.EncrypedShare)
	plaintextReader, err := age.Decrypt(encReader, identity...)
	if err != nil {
		// TODO, dont do the +%v
		return fmt.Errorf("unable to decrypt  %w", err)
	}
	plaintextShare, err := io.ReadAll(plaintextReader)
	if err != nil {
		// TODO, dont do the +%v
		return fmt.Errorf("unable to readdecrypted bytes  %w", err)
	}
	_, err = doc.ProcessShare(plaintextShare)
	return err
}

func (doc *SssDoc) ProcessKeyShareHandler(w http.ResponseWriter, r *http.Request) {
	//Parse params
}
