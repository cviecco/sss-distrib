package client

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"filippo.io/age"
	agearmor "filippo.io/age/armor"
	gpgcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/cviecco/sss-distrib/lib/sssdoc"
)

// We need 3 things:
//   - url
//   - encrypted key
//   - key passphrase
type ssdClient struct {
	baseURL       *url.URL
	ptPrivateKey  []byte //serialized key in plaintext for age
	gpgPrivateKey *gpgcrypto.Key

	filePath string
	keyType  int // This reuses the doc key types
	client   *http.Client

	logger *slog.Logger
}

// This fuct
// like: "age-keygen | grep SECRET |age -p -a"
func NewGenerateAgeKeyWithPassPhrase(outPath string, passphrase string, urlBase string, logger *slog.Logger) (*ssdClient, error) {
	out, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	defer out.Close()
	return newArmoredAgeKeyWithReaderAndPassphrase(out, passphrase, urlBase, logger)
}

func newArmoredAgeKeyWithReaderAndPassphrase(out io.Writer, passphrase string, urlBase string, logger *slog.Logger) (*ssdClient, error) {
	parsedURL, err := url.Parse(urlBase)
	if err != nil {
		return nil, err
	}
	sc := ssdClient{
		baseURL: parsedURL,
		//filePath: outPath,
		logger: logger,
	}
	agePQKey, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, err
	}

	sc.ptPrivateKey = []byte(agePQKey.String())

	in := bytes.NewReader(sc.ptPrivateKey)
	// now lets wrap the key

	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	withArmor := true
	testOnlyConfigureScryptIdentity(r)
	err = ageEncrypt([]age.Recipient{r}, in, out, withArmor)
	if err != nil {
		return nil, err
	}
	sc.keyType = sssdoc.KeyTypeAge
	return &sc, nil
}

var testOnlyConfigureScryptIdentity = func(*age.ScryptRecipient) {}

// Heavily inspired from age/cmd/age/age.go
// but we dont suppot pluggings (for simplicity of this code)
func ageEncrypt(recipients []age.Recipient, in io.Reader, out io.Writer, withArmor bool) error {

	a := agearmor.NewWriter(out)
	defer a.Close()
	out = a
	w, err := age.Encrypt(out, recipients...)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, in); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return nil
}

func guessKeyTypeFromArmoredBytes(data string) int {
	if strings.Contains(data, "----BEGIN PGP") {
		return sssdoc.KeyTypePGP
	}
	if strings.Contains(data, "----BEGIN AGE") {
		return sssdoc.KeyTypeAge
	}
	return sssdoc.KeyTypeUnknown
}

const maxKeySize = 102400 //100K
func LoadArmoredKeyWithPassPhrase(filepath string, passphrase string, logger *slog.Logger) (*ssdClient, error) {
	fin, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer fin.Close()
	return LoadArmoredKeyWithReaderAndPassPhrase(fin, passphrase, logger)
}
func LoadArmoredKeyWithReaderAndPassPhrase(fin io.Reader, passphrase string, logger *slog.Logger) (*ssdClient, error) {
	lr := io.LimitedReader{
		R: fin,
		N: maxKeySize,
	}
	armoredBytes, err := io.ReadAll(&lr)
	if err != nil {
		return nil, err
	}

	armoredReader := bytes.NewReader(armoredBytes)

	switch guessKeyTypeFromArmoredBytes(string(armoredBytes)) {
	case sssdoc.KeyTypeAge:
		return loadAgeKeyWithReaderAndPassPhrase(armoredReader, passphrase, logger)
	case sssdoc.KeyTypePGP:
		return loadGPGKeyWithReaderAndPassPhrase(armoredReader, passphrase, logger)
	default:
		return nil, fmt.Errorf("unable to guess file type")
	}
}

func loadAgeKeyWithReaderAndPassPhrase(armoredReader io.Reader, passphrase string, logger *slog.Logger) (*ssdClient, error) {
	sc := ssdClient{
		//filePath: filePath,
	}
	identities, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}

	var outBuffer bytes.Buffer
	err = ageDecrypt(armoredReader, &outBuffer, identities)
	if err != nil {
		return nil, err
	}
	sc.ptPrivateKey = outBuffer.Bytes()
	sc.client = http.DefaultClient //TODO, we need our own with sensible timeouts
	sc.keyType = sssdoc.KeyTypeAge
	sc.logger = logger
	return &sc, nil

}

func loadGPGKeyWithReaderAndPassPhrase(armoredReader io.Reader, passphrase string, logger *slog.Logger) (*ssdClient, error) {
	//load reader into []bytes
	armoredPrivate, err := io.ReadAll(armoredReader)
	if err != nil {
		return nil, err
	}
	privateKey, err := gpgcrypto.NewPrivateKeyFromArmored(string(armoredPrivate), []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("unable to parse armored gpg private key: %w", err)
	}
	sc := ssdClient{
		gpgPrivateKey: privateKey,
		client:        http.DefaultClient,
		keyType:       sssdoc.KeyTypePGP,
		logger:        logger,
	}
	return &sc, nil
}

func ageDecrypt(in io.Reader, out io.Writer, identities ...age.Identity) error {
	rr := bufio.NewReader(in) // not clear why bufio is actually needed
	ain := agearmor.NewReader(rr)

	r, err := age.Decrypt(ain, identities...)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, r); err != nil {
		return err
	}
	// Trigger the lazyOpener even if r is empty, if Copy succeeded.
	if _, err := out.Write(nil); err != nil {
		return err
	}
	return nil
}

func (sdc *ssdClient) SetBaseURL(urlBase string) error {
	parsedURL, err := url.Parse(urlBase)
	if err != nil {
		return err
	}
	sdc.baseURL = parsedURL
	return nil
}

func (sdc *ssdClient) GetPublicKey() ([]byte, error) {
	switch sdc.keyType {
	case sssdoc.KeyTypePGP:
		gpgPub, err := sdc.gpgPrivateKey.GetArmoredPublicKey()
		if err != nil {
			return nil, err
		}
		return []byte(gpgPub), nil
	case sssdoc.KeyTypeAge:
		pqident, err := age.ParseHybridIdentity(string(sdc.ptPrivateKey))
		if err != nil {
			return nil, err
		}
		publicKey := pqident.Recipient().String()
		return []byte(publicKey), nil
	default:
		return nil, fmt.Errorf("key type not supported")
	}
}

// Truncates to max bytes and escapes values from incomins tring
const maxloggableStringSize = 1000

func getLoggableString(in []byte) string {
	if in == nil {
		return ""
	}
	var truncated []byte
	if len(in) > maxloggableStringSize {
		truncated = in[:maxloggableStringSize]
	} else {
		truncated = in
	}
	return strconv.QuoteToASCII(string(truncated))
}

func (sdc *ssdClient) GetSuccessFullBytesFromRequest(r *http.Request) ([]byte, error) {
	resp, err := sdc.client.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read request body, resp code=%d err=%s", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK {
		stringToLog := getLoggableString(respBytes)
		sdc.logger.Debug("Not an OK response from server",
			slog.String("responsebody", stringToLog))

		return respBytes, fmt.Errorf("invalid status got %d", resp.StatusCode)
	}
	return respBytes, nil
}

func (sdc *ssdClient) findAndDecryptShare(shares []sssdoc.EncrypedShare) ([]byte, error) {
	var identity []age.Identity
	var err error
	if sdc.keyType == sssdoc.KeyTypeAge {
		idReader := bytes.NewReader([]byte(sdc.ptPrivateKey))
		identity, err = age.ParseIdentities(idReader)
		if err != nil {
			return nil, err
		}
	}
	//var plaintextShare []byte
	for i, share := range shares {
		// TODO, check with identifier, since we have NOT implemented this we need to try to decrypt with our key
		switch sdc.keyType {
		case sssdoc.KeyTypeAge:
			plaintextShare, err := sssdoc.AgeDecryptSingleShare(share, identity)
			if err != nil {
				sdc.logger.Debug("Share is not ours.", slog.Int("Index", i))
				continue
			}
			return plaintextShare, nil
		case sssdoc.KeyTypePGP:
			plaintextShare, err := sssdoc.GpgDecryptSingleShare(share, sdc.gpgPrivateKey)
			if err != nil {
				sdc.logger.Debug("Share is not ours.", slog.Int("Index", i))
				continue
			}
			return plaintextShare, nil
		default:
			return nil, fmt.Errorf("unknown key type %d", sdc.keyType)
		}
	}

	return nil, fmt.Errorf("No matching share found")
}

func (sdc *ssdClient) PushShareToServer() error {
	// check if ready (plaintext key loaded)
	// get the server doc
	// find share in doc
	// get the server pub
	// compute encrypted share
	// post encrypted share to servere

	serverDocURL := sdc.baseURL.JoinPath(sssdoc.DocInfoPath)
	docRequest, err := http.NewRequest(http.MethodGet, serverDocURL.String(), nil)
	if err != nil {
		return err
	}
	serializedDoc, err := sdc.GetSuccessFullBytesFromRequest(docRequest)
	if err != nil {
		return fmt.Errorf("error getting share doc: %w", err)
	}
	var shareDoc sssdoc.ShareDoc
	err = json.Unmarshal(serializedDoc, &shareDoc)
	if err != nil {
		return err
	}
	sdc.logger.Debug("Fetched and parsed share document")

	//now get the encryption data
	keyinfoPath := sdc.baseURL.JoinPath(sssdoc.KeyInfoPath)
	keyinfoRequest, err := http.NewRequest(http.MethodGet, keyinfoPath.String(), nil)

	keyInfoBody, err := sdc.GetSuccessFullBytesFromRequest(keyinfoRequest)
	if err != nil {
		return fmt.Errorf("errot getting keyinfodoc %w", err)
	}
	var keyInfo sssdoc.SssKexchangeKeys
	err = json.Unmarshal(keyInfoBody, &keyInfo)
	if err != nil {
		return err
	}
	sdc.logger.Debug("Fetched and Parsed keyinfo document")

	plaintextShare, err := sdc.findAndDecryptShare(shareDoc.Shares)
	if err != nil {
		sdc.logger.Debug("share not found", slog.String("shareDoc", string(serializedDoc)))
		return fmt.Errorf("unable to decrypt any share with our private key, match not found %w", err)
	}
	sdc.logger.Debug("Successfully Decrypted share from encryped doc")

	encMsg, err := sssdoc.NewAgeEncryptedMessage(plaintextShare, []byte(keyInfo.AgePubKeys[0]), sdc.baseURL.Hostname(), keyInfo.Base64ReplayNonce)
	if err != nil {
		return err
	}
	// Now we prepare the message to be posted
	b64EncShare := base64.URLEncoding.EncodeToString(encMsg)
	values := url.Values{sssdoc.EncMessageKey: []string{b64EncShare}}

	postSharePath := sdc.baseURL.JoinPath(sssdoc.ProcessSharePath)
	postEncShareReq, err := http.NewRequest(http.MethodPost, postSharePath.String(), strings.NewReader(values.Encode()))
	postEncShareReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	sharePostBytes, err := sdc.GetSuccessFullBytesFromRequest(postEncShareReq)
	if err != nil {
		return fmt.Errorf("failed to post share for processing %w", err)
	}
	var sssStatus sssdoc.SssShareStatus
	err = json.Unmarshal(sharePostBytes, &sssStatus)
	if err != nil {
		return err
	}
	//TODO compare status?
	return nil
}
