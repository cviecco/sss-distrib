package sssdoc

import (
	"crypto/rand"
	"fmt"
)

const (
	KeyTypeAge = iota
	KeyTypePGP
)

type EncrypedShare struct {
	Identifier           string
	PlaintextFingerPrint []byte
	EncrypedBlob         []byte
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

func genRandomString() ([]byte, error) {
	size := randomStringEntropyBytes
	rb := make([]byte, size)
	_, err := rand.Read(rb)
	if err != nil {
		return nil, err
	}
	return rb, nil

	//return base64.RawURLEncoding.EncodeToString(rb), nil
}

func newFromAgeKeysInternal(publicKeys []byte, identifiers []string, requiredShares int) (*ShareDoc, error) {
	return nil, fmt.Errorf("not implemented")
}
