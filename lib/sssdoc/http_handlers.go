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

const DocInfoPath = "/sss-distrib/sss-doc"
const KeyInfoPath = "/sss-distrib/key-info"
const ProcessSharePath = "/sss-distrib/process-share"

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

func (sd *SssProcessor) serveShareDocHandlerInternal(w http.ResponseWriter, r *http.Request) error {
	if sd.Doc == nil {
		return fmt.Errorf("No loaded doc")
	}
	payload, err := json.Marshal(sd.Doc)
	if err != nil {
		return fmt.Errorf("unable to marshal Doc")
	}
	// all errors after this are due to network errors and are not recoverable
	// this will be ignored
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(payload)
	return nil
}

func (sd *SssProcessor) ServeShareDocHandler(w http.ResponseWriter, r *http.Request) {
	err := sd.serveShareDocHandlerInternal(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

type SssKexchangeKeys struct {
	AgePubKeys        []string `json:"age_pub_keys"`
	Base64ReplayNonce string   `json:"b64_replay_nonce"`
}

func (sp *SssProcessor) GetKeyEchangeDocument() ([]byte, error) {
	replayNonce, err := sp.rProtector.GetProtectorBytes()
	if err != nil {
		return nil, err
	}
	b64replayNonce := base64.StdEncoding.EncodeToString(replayNonce)
	pubAgeString := sp.agePQKey.Recipient().String()
	payload, err := json.Marshal(SssKexchangeKeys{
		AgePubKeys:        []string{pubAgeString},
		Base64ReplayNonce: b64replayNonce,
	})
	return payload, nil

}

func (doc *SssProcessor) GetKeyExchangePublicKeysHandler(w http.ResponseWriter, r *http.Request) {
	payload, err := doc.GetKeyEchangeDocument()
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

type parsedEncrypedShareParams struct {
	EncrypedShare []byte
}

func (doc *SssProcessor) processEncrypedShareMessageFromParams(params parsedEncrypedShareParams) (shareId string, usererr error, internalerr error) {
	plaintextShare, err := DecryptValidateAgeMessage(params.EncrypedShare, []byte(doc.agePQKey.String()), doc.ProcesssingTarget, doc.rProtector)
	if err != nil {
		fmt.Printf("error decrypting message=%s", err)
		return "", err, nil
	}
	shareId, err = doc.ProcessShare(plaintextShare)
	return shareId, err, nil

}

// TODO, actually write a function that does the encoding for you and returns a request
const EncMessageKey = "b64encShare"

func (sp *SssProcessor) parseEncryptedShareFromParams(r *http.Request) (*parsedEncrypedShareParams, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, err
	}
	//fmt.Printf("parsing r==%+v", r)
	b64EncShare := r.FormValue(EncMessageKey)
	if b64EncShare == "" {
		return nil, fmt.Errorf("Missing required value  '%s'", EncMessageKey)
	}

	var rvalue parsedEncrypedShareParams
	rvalue.EncrypedShare, err = base64.URLEncoding.DecodeString(b64EncShare)
	if err != nil {
		return nil, fmt.Errorf("String is not b64 URL encoded %w", err)
	}
	return &rvalue, nil
}

// ProcessEncryptedShareMessageFromRequest allows to have a custom webhandler for the
// processing of the request.
func (sp *SssProcessor) ProcessEncrypedShareMessageFromRequest(r *http.Request) (identity string, userErr error, err error) {
	params, err := sp.parseEncryptedShareFromParams(r)
	if err != nil {
		return "", err, nil
	}
	identity, userErr, err = sp.processEncrypedShareMessageFromParams(*params)
	if err != nil || userErr != nil {
		return identity, userErr, err
	}
	return identity, nil, nil

}

// Keys should always be passed encrypted
func (sp *SssProcessor) ProcessKeyShareHandler(w http.ResponseWriter, r *http.Request) {

	_, userErr, err := sp.ProcessEncrypedShareMessageFromRequest(r)
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
	sp.logger.Debug("Processor: correctly processed key share")
	sp.GetShareStatusHandler(w, r)
}
