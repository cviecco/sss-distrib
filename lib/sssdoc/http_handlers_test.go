package sssdoc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/neilotoole/slogt/v2"
	"github.com/stretchr/testify/require"
)

///
// generate
// get public keys

func generateBaseTestingDoc(t *testing.T) ([]byte, *SssProcessor, []*age.X25519Identity, error) {
	logger := slogt.New(t)
	secret, err := generateSecret()
	require.NoError(t, err)
	var identities []*age.X25519Identity
	for i := 0; i < 3; i++ {
		identity, err := age.GenerateX25519Identity()
		require.NoError(t, err)
		identities = append(identities, identity)
	}
	/*
		recipientsStrings := []string{
			"age10hfzhu2hfw6wjn2vjjrqdke3yf5vzk9twwjz505tfv984tdegchs8kuwg6",
			"age1q292gkj5jmtqy74rcrym26tj3dz4xjnksuskkzveyw8xk9aamums4p44xj",
			"age1j3nhn07hllphue7d8n675csazfku8969c8j82g7kkfs0cepcpqfs9qykdz",
		}
	*/
	var recipients [][]byte
	strIdentities := []string{"1", "2", "3"}
	for i, identity := range identities {
		recipients = append(recipients, []byte(identity.Recipient().String()))
		strIdentities[i] = fmt.Sprintf("%d", i)
	}
	requiredShares := 2
	shareDoc, err := generateDocWithSecret(secret, recipients, strIdentities, requiredShares)
	require.NoError(t, err)
	sssdoc, err := NewProcessorFromShareDoc(shareDoc, logger)
	require.NoError(t, err)
	return secret, sssdoc, identities, nil
}

func TestGetShareStatusHandler(t *testing.T) {
	_, sd, _, err := generateBaseTestingDoc(t)
	require.NoError(t, err)
	req := httptest.NewRequest("GET", "/foo", nil)
	w := httptest.NewRecorder()

	sd.GetShareStatusHandler(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, resp.StatusCode, 200)

	//content type check
	require.Equal(t, resp.Header.Get("Content-Type"), jsonResponseContentType)

	// Data check
	var status SssShareStatus
	err = json.Unmarshal(body, &status)
	require.NoError(t, err)

	require.Equal(t, status.Required, 2)
	require.Equal(t, status.Processed, 0)

}

// Generated via claude (sonnet 5)
func TestServeShareDocHandler(t *testing.T) {
	_, sd, _, err := generateBaseTestingDoc(t)
	require.NoError(t, err)
	req := httptest.NewRequest("GET", "/foo", nil)
	w := httptest.NewRecorder()

	sd.ServeShareDocHandler(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, resp.StatusCode, 200)

	//content type check
	require.Equal(t, resp.Header.Get("Content-Type"), jsonResponseContentType)

	// Data check
	var returnedDoc ShareDoc
	err = json.Unmarshal(body, &returnedDoc)
	require.NoError(t, err)

	require.Equal(t, sd.Doc.RequiredShares, returnedDoc.RequiredShares)
	require.Equal(t, len(sd.Doc.Shares), len(returnedDoc.Shares))
	for i, share := range sd.Doc.Shares {
		require.Equal(t, share.Identifier, returnedDoc.Shares[i].Identifier)
	}
}

func TestGetKeyExchangePublicKeysHandler(t *testing.T) {
	_, sd, _, err := generateBaseTestingDoc(t)
	require.NoError(t, err)
	req := httptest.NewRequest("GET", "/foo", nil)
	w := httptest.NewRecorder()

	sd.GetKeyExchangePublicKeysHandler(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, resp.StatusCode, 200)
	fmt.Println(resp.Header.Get("Content-Type"))
	fmt.Println(string(body))

	//TODO: deserialize and esure it makes sense
	var serverKeys SssKexchangeKeys
	err = json.Unmarshal(body, &serverKeys)
	require.NoError(t, err)
	require.True(t, len(serverKeys.AgePubKeys) > 0)
	for _, ageKey := range serverKeys.AgePubKeys {
		require.True(t, strings.HasPrefix(ageKey, "age1"))
	}
}

func TestProcessEncryptedShareFromParamsSuccess(t *testing.T) {
	_, sd, x25519identities, err := generateBaseTestingDoc(t)
	require.NoError(t, err)
	// Now get the doc.
	//encryptedShare := sd.Doc.Shares[0].EncryptedBlob
	for i, x25519ident := range x25519identities {
		idReader := bytes.NewReader([]byte(x25519ident.String()))
		identity, err := age.ParseIdentities(idReader)
		ptShare, err := AgeDecryptSingleShare(sd.Doc.Shares[i], identity)
		require.NoError(t, err)

		//With the now we encrypt the plaintextshare with the sd key
		//encShare, _, err := encryptDataWithPublic(ptShare, []byte(sd.agePQKey.Recipient().String()))
		//require.NoError(t, err)
		//encMsg, err := NewAgeEncryptedMessage(ptShare, []byte(keyInfo.AgePubKeys[0]), "hostname", keyInfo.Base64ReplayNonce)
		nonce, err := sd.rProtector.GetProtectorBytes()
		require.NoError(t, err)
		b64nonce := base64.StdEncoding.EncodeToString(nonce)
		encMsg, err := NewAgeEncryptedMessage(ptShare, []byte(sd.agePQKey.Recipient().String()), sd.ProcesssingTarget, b64nonce)
		require.NoError(t, err)
		b64EncShare := base64.URLEncoding.EncodeToString(encMsg)
		values := url.Values{EncMessageKey: []string{b64EncShare}}
		req := httptest.NewRequest("POST", "/", strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		sd.ProcessKeyShareHandler(w, req)
		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)

		//t.Logf("body: %s", string(body))
		require.Equal(t, 200, resp.StatusCode)
		var status SssShareStatus
		err = json.Unmarshal(body, &status)
		require.Equal(t, status.Processed, i+1)

		require.Equal(t, len(sd.processedShare), i+1)
	}

}

func TestEncryptDecryptMessage(t *testing.T) {
	//hybridKey, err := age.New

	// First valid round trip
	agePQKey, err := age.GenerateHybridIdentity()
	require.NoError(t, err)

	rprotector, err := NewReplayProtector()
	require.NoError(t, err)

	payloadText := "hello"
	messageSubject := "target1"
	nonce, err := rprotector.GetProtectorBytes()
	require.NoError(t, err)
	b64nonce := base64.StdEncoding.EncodeToString(nonce)

	encMessage, err := NewAgeEncryptedMessage([]byte(payloadText),
		[]byte(agePQKey.Recipient().String()), messageSubject, b64nonce)
	require.NoError(t, err)
	//now the return
	payload, err := DecryptValidateAgeMessage(encMessage, []byte(agePQKey.String()), messageSubject, rprotector)
	require.NoError(t, err)
	require.Equal(t, payloadText, string(payload))

	// now with busted subject
	_, err = DecryptValidateAgeMessage(encMessage, []byte(agePQKey.Recipient().String()), "randomSubject", rprotector)
	require.Error(t, err)

	// Now with invalid nonce
	invalidNonceencMessage, err := NewAgeEncryptedMessage([]byte(payloadText),
		[]byte(agePQKey.Recipient().String()), messageSubject,
		base64.StdEncoding.EncodeToString([]byte("1234")))
	_, err = DecryptValidateAgeMessage(invalidNonceencMessage,
		[]byte(agePQKey.String()), messageSubject, rprotector)
	require.Error(t, err)

}
