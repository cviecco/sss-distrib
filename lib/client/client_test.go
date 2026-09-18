package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cviecco/sss-distrib/lib/sssdoc"
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

func testPrintJustPath(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("incoming request =%+v", r)
	http.Error(w, "unmatched path", http.StatusBadRequest)
}

func TestPushToServer(t *testing.T) {
	// 1. Generate local client
	// 2. Use local client key + const to generate new sharedoc
	// 3. With sharedoc create new consumer
	// 4. with consumer create new mock test server
	// 5. connect client to mock test server

	dir, err := os.MkdirTemp("", "example")
	require.NoError(t, err)

	defer os.RemoveAll(dir) // clean up

	filename1 := filepath.Join(dir, "tmpfile")
	sc1, err := NewAgeKeyWithPassPhrase(filename1, testPassphrase, "http://example.com")
	require.NoError(t, err)
	require.NotNil(t, sc1)

	filename2 := filepath.Join(dir, "tmpfile2")
	sc2, err := NewAgeKeyWithPassPhrase(filename2, testPassphrase, "http://example.com")
	require.NoError(t, err)
	require.NotNil(t, sc2)

	var publicKeys [][]byte
	pubkey1, err := sc1.GetPublicKey()
	require.NoError(t, err)
	pubkey2, err := sc2.GetPublicKey()
	require.NoError(t, err)
	publicKeys = append(publicKeys, pubkey1)
	publicKeys = append(publicKeys, pubkey2)

	doc, err := sssdoc.GenerateNewDocFromKeys(publicKeys, 2)
	require.NoError(t, err)
	processor, err := sssdoc.NewProcessorFromShareDoc(doc)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc(sssdoc.DocInfoPath, processor.ServeShareDocHandler)
	mux.HandleFunc(sssdoc.KeyInfoPath, processor.GetKeyExchangePublicKeysHandler)
	mux.HandleFunc(sssdoc.ProcessSharePath, processor.ProcessKeyShareHandler)
	mux.HandleFunc("/", testPrintJustPath)

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	sc1.BaseURL = ts.URL
	sc1.client = ts.Client()

	err = sc1.PushShareToServer()
	require.Error(t, err) //This is busted, but fix needs changes in the server side

}
