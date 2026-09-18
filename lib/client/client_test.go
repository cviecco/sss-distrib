package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const testPassphrase = "12345" // same as my lugggage
const ageArmorPrefix = "-----BEGIN AGE ENCRYPTED FILE-----"

func TestSimpleFileRoundTripAge(t *testing.T) {
	dir, err := os.MkdirTemp("", "example")
	require.NoError(t, err)

	defer os.RemoveAll(dir) // clean up

	filename := filepath.Join(dir, "tmpfile")

	sc1, err := NewAgeKeyWithPassPhrase(filename, testPassphrase, "http://example.com")
	require.NoError(t, err)
	require.NotNil(t, sc1)

	//minor saniry check
	filedata, err := os.ReadFile(filename)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(filedata), ageArmorPrefix))

	//fmt.Printf("filedata=%s", string(filedata))

	sc2, err := LoadAgeKeyWithPassPhrase(filename, testPassphrase)
	require.NoError(t, err)
	require.NotNil(t, sc2)

	// PrivateKeys should match
	require.Equal(t, sc1.ptPrivateKey, sc2.ptPrivateKey)

	//Public keys must match
	pub1, err := sc1.GetPublicKey()
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(pub1), "age1"))
	pub2, err := sc2.GetPublicKey()
	require.NoError(t, err)
	require.Equal(t, pub1, pub2)
}

func TestGetSuccessfullBytesFromRequest(t *testing.T) {
	// new client!

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			http.Error(w, "bad method", http.StatusBadRequest)
			return
		}
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	client := ssdClient{
		BaseURL: ts.URL,
		client:  ts.Client(),
	}
	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	bodyBytes, err := client.GetSuccessFullBytesFromRequest(req)
	require.NoError(t, err)
	require.NotNil(t, bodyBytes)

	//now a failed one, with a fail due to not being 200
	badreq, err := http.NewRequest(http.MethodPatch, ts.URL, nil)
	require.NoError(t, err)
	_, err = client.GetSuccessFullBytesFromRequest(badreq)
	require.Error(t, err)

	// now a filed one witha. bad url
	badreq2, err := http.NewRequest(http.MethodGet, "http:/example.com", nil)
	require.NoError(t, err)
	_, err = client.GetSuccessFullBytesFromRequest(badreq2)
	require.Error(t, err)

}
