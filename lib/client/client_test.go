package client

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/cviecco/sss-distrib/lib/sssdoc"
	"github.com/neilotoole/slogt/v2"
	"github.com/stretchr/testify/require"
)

const testPassphrase = "12345" // same as my lugggage
const ageArmorPrefix = "-----BEGIN AGE ENCRYPTED FILE-----"

const pgp_sss_test_1 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEanuV0RYJKwYBBAHaRw8BAQdAreB93UG39zZbszjm4qZAPkLIsTZzFiJ0EkZm
4D3h9IX+BwMCTFbqe4/9FiL/SYTNV1eQnYN5VZOIwN3sEPL/fPkTB/pf0nm07Pol
SLo4VPYiLXIcR4dt1KSmx/tHEgM4aQVrbTWsSV8fvlZFFEM/MGC5KrQrc3NzX3Rl
c3Rfa2V5XzEgPHNzc190ZXN0X2tleV8xQGV4YW1wbGUuY29tPoi1BBMWCgBdFiEE
75wm5LSQ1mcsE+kP6BosHkovdwEFAmp7ldEbFIAAAAAABAAObWFudTIsMi41KzEu
MTIsMCwzAhsDBQkFo5qABQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEOga
LB5KL3cB4KIBANir8Gw1Y8E1xL2TAtIuHEatoSY2GczBa/5m/IOxHo7wAQCLgoDl
sQvk/mK3Wzad4gbhAQboy3pqngwxvAazpDvnApyLBGp7ldESCisGAQQBl1UBBQEB
B0BYOaOjpP3NqtQAaI9FdVvRYrR1xiZ/HmovJfibrq/8JgMBCAf+BwMCKVb6Rp6U
/k3/w9qhxMHuD71aglHVJrryJXjnIgnbm4g+vMewjXnVkTdRpsDuTJyEx/8hUPqi
2QtOGRK6Xib96W1T88RNxoGtbkcOeUmE7YiaBBgWCgBCFiEE75wm5LSQ1mcsE+kP
6BosHkovdwEFAmp7ldEbFIAAAAAABAAObWFudTIsMi41KzEuMTIsMCwzAhsMBQkF
o5qAAAoJEOgaLB5KL3cBniMBALEmun8x14Vi8wVNaxlzxXrhsqoCkvjO7xzE0fPv
2Wd3AQDr7IcJYSptY4uDFiu7pFr2NkYpHZ6ttZ8B2XphCIGECQ==
=2wd5
-----END PGP PRIVATE KEY BLOCK-----`

func TestSimpleFileRoundTripAge(t *testing.T) {
	logger := slogt.New(t)
	dir, err := os.MkdirTemp("", "example")
	require.NoError(t, err)

	defer os.RemoveAll(dir) // clean up

	filename := filepath.Join(dir, "tmpfile")

	sc1, err := NewGenerateAgeKeyWithPassPhrase(filename, testPassphrase, "http://example.com", logger)
	require.NoError(t, err)
	require.NotNil(t, sc1)

	//minor saniry check
	filedata, err := os.ReadFile(filename)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(filedata), ageArmorPrefix))

	//fmt.Printf("filedata=%s", string(filedata))

	//sc2, err := LoadAgeKeyWithPassPhrase(filename, testPassphrase)
	sc2, err := LoadArmoredKeyWithPassPhrase(filename, testPassphrase, logger)
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

	logger := slogt.New(t)
	client := ssdClient{
		//BaseURL: ts.URL,
		client: ts.Client(),
		logger: logger,
	}
	err := client.SetBaseURL(ts.URL)
	require.NoError(t, err)
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

	logger := slogt.New(t)

	filename1 := filepath.Join(dir, "tmpfile")
	sc1, err := NewGenerateAgeKeyWithPassPhrase(filename1, testPassphrase, "http://example.com", logger)
	require.NoError(t, err)
	require.NotNil(t, sc1)

	filename2 := filepath.Join(dir, "tmpfile2")
	sc2, err := NewGenerateAgeKeyWithPassPhrase(filename2, testPassphrase, "http://example.com", logger)
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
	parsedServerURL, err := url.Parse(ts.URL)
	require.NoError(t, err)
	processor.ProcesssingTarget = parsedServerURL.Hostname()

	err = sc1.SetBaseURL(ts.URL)
	require.NoError(t, err)
	sc1.client = ts.Client()

	err = sc1.PushShareToServer()
	require.NoError(t, err) //This is busted, but fix needs changes in the server side

}

func TestLoadPGPGArmoredKey(t *testing.T) {
	logger := slogt.New(t)
	reader := bytes.NewReader([]byte(pgp_sss_test_1))
	sdc, err := loadGPGKeyWithReaderAndPassPhrase(reader, testPassphrase, logger)
	require.NoError(t, err)
	require.NotNil(t, sdc)

	//Now with the generic entry
	dir, err := os.MkdirTemp("", "example")
	require.NoError(t, err)

	defer os.RemoveAll(dir) // clean up

	filename1 := filepath.Join(dir, "tmpfile")
	keyFile, err := os.OpenFile(filename1, os.O_RDWR|os.O_CREATE, 0644)
	require.NoError(t, err)
	_, err = keyFile.WriteString(pgp_sss_test_1)
	require.NoError(t, err)
	err = keyFile.Close()
	require.NoError(t, err)

	sdc2, err := LoadArmoredKeyWithPassPhrase(filename1, testPassphrase, logger)
	require.NoError(t, err)
	require.NotNil(t, sdc2)

	pub1, err := sdc.GetPublicKey()
	require.NoError(t, err)
	pub2, err := sdc2.GetPublicKey()
	require.Equal(t, pub1, pub2)
}

func TestFindAndDecryptShare(t *testing.T) {
	logger := slogt.New(t)
	var outBuffer bytes.Buffer
	sdc, err := newArmoredAgeKeyWithReaderAndPassphrase(&outBuffer, testPassphrase, "http://example.com", logger)
	require.NoError(t, err)
	require.NotNil(t, sdc)

	_, err = sdc.GetPublicKey()
	require.NoError(t, err)

}

// Generated by Claude (sonnet 5)
func TestFindAndDecryptShareCases(t *testing.T) {
	logger := slogt.New(t)

	// Load a gpg client from the existing test private key.
	gpgReader := bytes.NewReader([]byte(pgp_sss_test_1))
	gpgClient, err := loadGPGKeyWithReaderAndPassPhrase(gpgReader, testPassphrase, logger)
	require.NoError(t, err)
	gpgPub, err := gpgClient.GetPublicKey()
	require.NoError(t, err)

	// Generate an age identity that will have a matching share in the doc.
	ageIdentity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	agePub := []byte(ageIdentity.Recipient().String())

	// Build a share doc with one age share and one gpg share.
	shareDoc, err := sssdoc.GenerateNewDocFromKeysAndIdentifiers(
		[][]byte{agePub, gpgPub},
		[]string{"age-share", "gpg-share"},
		2,
	)
	require.NoError(t, err)
	require.Len(t, shareDoc.Shares, 2)
	ageShare := shareDoc.Shares[0]
	gpgShare := shareDoc.Shares[1]

	t.Run("finds a gpg encrypted share", func(t *testing.T) {
		plaintext, err := gpgClient.findAndDecryptShare(shareDoc.Shares)
		require.NoError(t, err)
		fp := sha512.Sum512(plaintext)
		require.Equal(t, gpgShare.PlaintextFingerPrint, fp[:])
	})

	t.Run("finds an age encrypted share", func(t *testing.T) {
		ageClient := ssdClient{
			ptPrivateKey: []byte(ageIdentity.String()),
			keyType:      sssdoc.KeyTypeAge,
			logger:       logger,
		}
		plaintext, err := ageClient.findAndDecryptShare(shareDoc.Shares)
		require.NoError(t, err)
		fp := sha512.Sum512(plaintext)
		require.Equal(t, ageShare.PlaintextFingerPrint, fp[:])
	})

	t.Run("does not find a matching share", func(t *testing.T) {
		strangerIdentity, err := age.GenerateX25519Identity()
		require.NoError(t, err)
		strangerClient := ssdClient{
			ptPrivateKey: []byte(strangerIdentity.String()),
			keyType:      sssdoc.KeyTypeAge,
			logger:       logger,
		}
		_, err = strangerClient.findAndDecryptShare(shareDoc.Shares)
		require.Error(t, err)
	})
}
func TestGetLoggableString(t *testing.T) {
	testCases := []struct {
		name string
		in   []byte
	}{
		{
			name: "nil input",
			in:   nil,
		},
		{
			name: "empty input",
			in:   []byte{},
		},
		{
			name: "small input, well under limit",
			in:   []byte("hello world"),
		},
		{
			name: "input containing bytes that need escaping",
			in:   []byte("hello\tworld\n\"quoted\"\x00\xffbytes"),
		},
		{
			name: "input one byte under maxloggableStringSize",
			in:   bytes.Repeat([]byte("a"), maxloggableStringSize-1),
		},
		{
			name: "input exactly maxloggableStringSize",
			in:   bytes.Repeat([]byte("a"), maxloggableStringSize),
		},
		{
			name: "input one byte over maxloggableStringSize",
			in:   bytes.Repeat([]byte("a"), maxloggableStringSize+1),
		},
		{
			name: "input well over maxloggableStringSize",
			in:   bytes.Repeat([]byte("a"), maxloggableStringSize*3),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := getLoggableString(tc.in)

			if tc.in == nil {
				require.Equal(t, "", got)
				return
			}

			expectedLen := len(tc.in)
			if expectedLen > maxloggableStringSize {
				expectedLen = maxloggableStringSize
			}
			want := strconv.QuoteToASCII(string(tc.in[:expectedLen]))
			require.Equal(t, want, got)
		})
	}
}
