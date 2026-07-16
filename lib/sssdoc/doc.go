package sssdoc

import (
	"bytes"
	"crypto/sha512"
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

	//1 Generate secret and shares
	//2. Create a new encryptedShare with each share
	//3. Combine to make a new doc

	plaintextShares, err := generateAndSplitSecret(requiredShares, len(recipients))
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
	return &outDoc, nil

	//return nil, fmt.Errorf("not implemented")
}
