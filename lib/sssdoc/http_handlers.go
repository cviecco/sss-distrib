package sssdoc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"filippo.io/age"
)

const DocInfoPath = "sss-distrib/sss-doc"
const KeyInfoPath = "sss-distrib/key-info"
const ProcessSharePath = "sss-distrib/process-share"

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
	AgePubKeys        []string `json:"age_pub_keys"`
	Base64ReplayNonce string   `json:"b64_replay_nonce"`
}

func (doc *SssProcessor) GetKeyExchangePublicKeysHandler(w http.ResponseWriter, r *http.Request) {
	replayNonce, err := doc.rProtector.GetProtectorBytes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	b64replayNonce := base64.StdEncoding.EncodeToString(replayNonce)
	pubAgeString := doc.agePQKey.Recipient().String()
	payload, err := json.Marshal(SssKexchangeKeys{
		AgePubKeys:        []string{pubAgeString},
		Base64ReplayNonce: b64replayNonce,
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

type DataMessage struct {
	B64Nonce string `json:"b64nonce"` // replay attack prevention, as there is no common clock
	Target   string `json:"sub"`
	Payload  []byte `json:"payload"`
}

func NewAgeEncryptedMessage(payload []byte, publickey []byte, subject string, rpNonce string) ([]byte, error) {
	return newAgeEncryptedMessageInternal(payload, publickey, subject, rpNonce, time.Now())
}

func newAgeEncryptedMessageInternal(payload []byte, pubicKey []byte, subject string, rpNonce string, sentTime time.Time) ([]byte, error) {
	Message := DataMessage{
		Payload:  payload,
		Target:   subject,
		B64Nonce: rpNonce,
	}
	serializedMessage, err := json.Marshal(Message)
	if err != nil {
		return nil, err
	}
	encMessage, _, err := encryptDataWithPublic(serializedMessage, pubicKey)
	if err != nil {
		return nil, err
	}
	return encMessage, nil
}

// Returns the payload
func DecryptValidateAgeMessage(encryptedMessage []byte, privateKey []byte, subject string, rpchecker replayChecker) ([]byte, error) {
	return decryptValidateAgeMessageInternal(encryptedMessage, privateKey, subject, rpchecker)
}

func decryptValidateAgeMessageInternal(encryptedMessage []byte, privateKey []byte, subject string, rpchecker replayChecker) ([]byte, error) {
	idReader := bytes.NewReader(privateKey)
	identity, err := age.ParseIdentities(idReader)
	if err != nil {
		return nil, err
	}
	encReader := bytes.NewReader(encryptedMessage)
	plaintextReader, err := age.Decrypt(encReader, identity...)
	if err != nil {
		return nil, err
	}
	serializedMessage, err := io.ReadAll(plaintextReader)
	if err != nil {
		return nil, err
	}
	var message DataMessage
	err = json.Unmarshal(serializedMessage, &message)
	if err != nil {
		return nil, err
	}
	//Now validate
	if message.Target != subject {
		return nil, fmt.Errorf("invalid target")
	}
	rawReplay, err := base64.StdEncoding.DecodeString(message.B64Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce encoding")
	}
	replayPass := rpchecker.CheckReplayExists(rawReplay)
	if !replayPass {
		return nil, fmt.Errorf("unknown/bad replace nonce")
	}
	return message.Payload, nil
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
	// Here we check for replay + id

	_, err = doc.ProcessShare(plaintextShare)
	return nil, err
}

// TODO, actually write a function that does the encoding for you and returns a request
const EncMessageKey = "b64encShare"

func (sp *SssProcessor) ParseEncryptedShareFromParams(w http.ResponseWriter, r *http.Request) (*processEncrypedShareParams, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, err
	}
	//fmt.Printf("parsing r==%+v", r)
	b64EncShare := r.FormValue(EncMessageKey)
	if b64EncShare == "" {
		return nil, fmt.Errorf("Missing required value  '%s'", EncMessageKey)
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
