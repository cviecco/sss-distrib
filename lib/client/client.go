package client

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	//"path"

	"filippo.io/age"
	agearmor "filippo.io/age/armor"
	"github.com/cviecco/sss-distrib/lib/sssdoc"
)

func mainx() {
	fmt.Println("vim-go")
}

// We need 3 things:
//   - url
//   - encrypted key
//   - key passphrase
type ssdClient struct {
	BaseURL      string
	ptPrivateKey []byte //serialized key in plaintext

	//passphrase   string
	filePath string
	keyType  int // should be an enum
	client   *http.Client
}

// almost like: "age-keygen |age -p -a"
func NewAgeKeyWithPassPhrase(outPath string, passphrase string, urlBase string) (*ssdClient, error) {
	sc := ssdClient{
		BaseURL:  urlBase,
		filePath: outPath,
	}
	agePQKey, err := age.GenerateHybridIdentity()
	if err != nil {
		return nil, err
	}

	out, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	defer out.Close()

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

// The file is assumed to be an armored key file
func LoadAgeKeyWithPassPhrase(filePath string, passphrase string) (*ssdClient, error) {
	sc := ssdClient{
		filePath: filePath,
	}
	//identities := []age.Identity{} //Need to fix this one

	identities, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}

	fin, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	var outBuffer bytes.Buffer
	err = ageDecrypt(fin, &outBuffer, identities)
	if err != nil {
		return nil, err
	}
	sc.ptPrivateKey = outBuffer.Bytes()
	sc.client = http.DefaultClient
	sc.keyType = sssdoc.KeyTypeAge
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

func (sdc *ssdClient) GetPublicKey() ([]byte, error) {
	pqident, err := age.ParseHybridIdentity(string(sdc.ptPrivateKey))
	if err != nil {
		return nil, err
	}
	publicKey := pqident.Recipient().String()
	return []byte(publicKey), nil
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
		return respBytes, fmt.Errorf("inbalid status got %d", resp.StatusCode)
	}
	return respBytes, nil
}

func (sdc *ssdClient) PushShareToServer() error {
	// check if ready (plaintext key loaded)
	// get the server doc
	// find share in doc
	// get the server pub
	// compute encrypted share
	// post encrypted share to servere

	serverDocPath := sdc.BaseURL + sssdoc.DocInfoPath
	docRequest, err := http.NewRequest(http.MethodGet, serverDocPath, nil)
	if err != nil {
		return err
	}
	serializedDoc, err := sdc.GetSuccessFullBytesFromRequest(docRequest)
	if err != nil {
		return err
	}
	var shareDoc sssdoc.ShareDoc
	err = json.Unmarshal(serializedDoc, &shareDoc)
	if err != nil {
		return err
	}

	//now get the encryption data
	keyinfoPath := sdc.BaseURL + sssdoc.KeyInfoPath
	keyinfoRequest, err := http.NewRequest(http.MethodGet, keyinfoPath, nil)

	keyInfoBody, err := sdc.GetSuccessFullBytesFromRequest(keyinfoRequest)
	/*
		keyInfoResponse, err := sdc.client.Do(keyinfoRequest)
		if err != nil {
			return err
		}
		if keyInfoResponse.StatusCode != http.StatusOK {
			return fmt.Errorf("Invalid sttus code, got %d", keyInfoResponse.StatusCode)
		}
		keyInfoBody, err := io.ReadAll(keyInfoResponse.Body)
	*/
	if err != nil {
		return err
	}
	var keyInfo sssdoc.SssKexchangeKeys
	err = json.Unmarshal(keyInfoBody, keyInfo)
	if err != nil {
		return err
	}

	shareFound := false
	idReader := bytes.NewReader([]byte(sdc.ptPrivateKey))
	identity, err := age.ParseIdentities(idReader)
	if err != nil {
		return err
	}
	var plaintextShare []byte
shareDocLoop:
	for _, share := range shareDoc.Shares {
		// TODO, check with identifier, since we have NOT implemented this we need to try to decrypt with our key
		switch sdc.keyType {
		case sssdoc.KeyTypeAge:
			plaintextShare, err = sssdoc.AgeDecryptSingleShare(share, identity)
			if err != nil {
				continue
			}
			shareFound = true
			break shareDocLoop
		}
	}
	if !shareFound {
		return fmt.Errorf("unable to decrypt any share with our private key, match not found")
	}

	fmt.Printf("llen =%d", len(plaintextShare))
	//encMessage, err := sssdoc.NewAgeEncryptedMessage(plaintextShare,[]byte(keyInfo.AgePubKeys[0], "the Hostname", keyInfo.Base64ReplayNonce)
	encMsg, err := sssdoc.NewAgeEncryptedMessage(plaintextShare, []byte(keyInfo.AgePubKeys[0]), "hostname", keyInfo.Base64ReplayNonce)
	if err != nil {
		return err
	}
	// Now we prepare the message to be posted
	b64EncShare := base64.URLEncoding.EncodeToString(encMsg)
	values := url.Values{sssdoc.EncMessageKey: []string{b64EncShare}}
	postSharePath := sdc.BaseURL + sssdoc.ProcessSharePath
	postEncShareReq, err := http.NewRequest(http.MethodPost, postSharePath, strings.NewReader(values.Encode()))
	postEncShareReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	sharePostBytes, err := sdc.GetSuccessFullBytesFromRequest(postEncShareReq)
	if err != nil {
		return err
	}
	var sssStatus sssdoc.SssShareStatus
	err = json.Unmarshal(sharePostBytes, sssStatus)
	if err != nil {
		return err
	}
	//TODO compare status?
	return nil

}
