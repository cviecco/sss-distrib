package sssdoc

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"

	"filippo.io/age"
)

const (
	KeyTypeAge = iota
	KeyTypePGP
)

type EncrypedShare struct {
	Identifier           string
	PlaintextFingerPrint []byte
	EncryptedBlob        []byte
	KeyType              int
	PublicKey            []byte
}

type ShareDoc struct {
	Shares         []EncrypedShare
	RequiredShares int
}

type SssDoc struct {
	sharedSecret   []byte
	processedShare map[string][]byte
	Doc            ShareDoc
}

func NewSSSDoc() (*SssDoc, error) {

	return nil, fmt.Errorf("not implemented")
}

func GenerateNewDocFromAgeKeys(publicKeys []byte, identifiers []string, requiredShares int) (*ShareDoc, error) {
	return nil, fmt.Errorf("not implemented")
}

func NewSSDocFromShareDocJSON([]byte) (*SssDoc, error) {
	return nil, fmt.Errorf("not implemented")
}

const randomStringEntropyBytes = 32

/*
func genRandomString() ([]byte, error) {
}
*/
func newFromAgeKeysInternal(recipients [][]byte, identifiers []string, requiredShares int) (*ShareDoc, error) {
	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}
	return ageGenerateDocWithSecret(secret, recipients, identifiers, requiredShares)
}

func ageGenerateDocWithSecret(secret []byte, recipients [][]byte, identifiers []string, requiredShares int) (*ShareDoc, error) {
	//func newFromAgeKeysInternal(recipients [][]byte, identifiers []string, requiredShares int) (*ShareDoc, error) {

	//1 Generate secret and shares
	//2. Create a new encryptedShare with each share
	//3. Combine to make a new doc

	plaintextShares, err := withSecretGenerateSecretShares(secret, requiredShares, len(recipients))
	if err != nil {
		return nil, err
	}
	var outDoc ShareDoc
	for i, recipient := range recipients {
		identityBuffer := bytes.NewBuffer(recipient)
		parsedRecipient, err := age.ParseRecipients(identityBuffer)
		if err != nil {
			return nil, err
		}
		plaintextData := plaintextShares[i]
		plaintextFP := sha512.Sum512(plaintextShares[i])
		ptReader := bytes.NewReader(plaintextData)
		//var encBuffer bytes.Buffer
		encReader, err := age.EncryptReader(ptReader, parsedRecipient[0])
		if err != nil {
			return nil, fmt.Errorf("Unable to encrypt reader %w", err)
		}
		encData, err := io.ReadAll(encReader)

		docShare := EncrypedShare{
			Identifier:           identifiers[i],
			EncryptedBlob:        encData,
			PlaintextFingerPrint: plaintextFP[:],
			KeyType:              KeyTypeAge,
			// PublicKey
		}
		outDoc.Shares = append(outDoc.Shares, docShare)

	}
	outDoc.RequiredShares = requiredShares
	return &outDoc, nil
}

func ageDecryptSingleShare(share EncrypedShare, identities []age.Identity) ([]byte, error) {
	encReader := bytes.NewReader(share.EncryptedBlob)
	plaintextReader, err := age.Decrypt(encReader, identities...)
	if err != nil {
		// TODO, dont do the +%v
		return nil, fmt.Errorf("unable to decrypt %+v %w", share, err)
	}
	return io.ReadAll(plaintextReader)
}

func (sd *SssDoc) ProcessShare(plaintextShare []byte) ([]byte, error) {
	shareFP := sha512.Sum512(plaintextShare)
	b64ShareFP := base64.StdEncoding.EncodeToString(shareFP[:])

	for _, encShare := range sd.Doc.Shares {
		if !bytes.Equal(shareFP[:], encShare.PlaintextFingerPrint) {
			continue
		}
		//encS
		_, ok := sd.processedShare[b64ShareFP]
		if ok {
			return sd.sharedSecret, nil
		}
		sd.processedShare[b64ShareFP] = plaintextShare
		shareSet := [][]byte{}
		for _, share := range sd.processedShare {
			shareSet = append(shareSet, share)
		}
		if len(shareSet) < sd.Doc.RequiredShares {
			return nil, nil
		}
		secret, err := combineSecret(shareSet)
		if err != nil {
			return nil, err
		}
		// TODO:: ensure new is same if not nil
		sd.sharedSecret = secret
		return sd.sharedSecret, nil
	}
	return sd.sharedSecret, fmt.Errorf("Suggested Share does not match any fingerprint")
}
