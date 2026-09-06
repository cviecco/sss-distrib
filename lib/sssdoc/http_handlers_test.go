package sssdoc

import (
	"fmt"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

///
// generate
// get public keys

func generateBaseTestingDoc(t *testing.T) ([]byte, *SssDoc, error) {
	secret, err := generateSecret()
	require.NoError(t, err)

	recipientsStrings := []string{
		"age10hfzhu2hfw6wjn2vjjrqdke3yf5vzk9twwjz505tfv984tdegchs8kuwg6",
		"age1q292gkj5jmtqy74rcrym26tj3dz4xjnksuskkzveyw8xk9aamums4p44xj",
		"age1j3nhn07hllphue7d8n675csazfku8969c8j82g7kkfs0cepcpqfs9qykdz",
	}
	var recipients [][]byte
	identities := []string{"1", "2", "3"}
	for i, recipient := range recipientsStrings {
		recipients = append(recipients, []byte(recipient))
		identities[i] = fmt.Sprintf("%d", i)
	}
	requiredShares := 2
	shareDoc, err := generateDocWithSecret(secret, recipients, identities, requiredShares)
	require.NoError(t, err)
	sssdoc, err := NewSSSDocFromShareDoc(shareDoc)
	require.NoError(t, err)
	return secret, sssdoc, nil
}

func TestGetShareStatusHandler(t *testing.T) {
	_, sd, err := generateBaseTestingDoc(t)
	require.NoError(t, err)
	req := httptest.NewRequest("GET", "/foo", nil)
	w := httptest.NewRecorder()

	sd.GetShareStatusHandler(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, resp.StatusCode, 200)
	//fmt.Println(resp.StatusCode)
	fmt.Println(resp.Header.Get("Content-Type"))
	fmt.Println(string(body))

	//TODO: deserialize and esure it makes sense
}

func TestGetKeyExchangePublicKeysHandler(t *testing.T) {
	_, sd, err := generateBaseTestingDoc(t)
	require.NoError(t, err)
	req := httptest.NewRequest("GET", "/foo", nil)
	w := httptest.NewRecorder()

	sd.GetKeyExchangePublicKeysHandler(w, req)
	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, resp.StatusCode, 200)
	//fmt.Println(resp.StatusCode)
	fmt.Println(resp.Header.Get("Content-Type"))
	fmt.Println(string(body))

	//TODO: deserialize and esure it makes sense

}
