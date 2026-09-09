package client

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	agearmor "filippo.io/age/armor"
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
