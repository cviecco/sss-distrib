package sssdoc

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

const (
	KeyTypeUnknown = iota
	KeyTypeAge
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
	Doc            *ShareDoc
}

func NewSSSDoc() (*SssDoc, error) {

	return nil, fmt.Errorf("not implemented")
}

func GenerateNewDocFromAgeKeys(publicKeys []byte, identifiers []string, requiredShares int) (*ShareDoc, error) {
	return nil, fmt.Errorf("not implemented")
}

func NewSSDocFromShareDocJSON(serializedDoc []byte) (*SssDoc, error) {
	var parsedDoc ShareDoc
	err := json.Unmarshal(serializedDoc, &parsedDoc)
	if err != nil {
		return nil, err
	}

	return NewSSSDocFromShareDoc(&parsedDoc), nil
}

func NewSSSDocFromShareDoc(sd *ShareDoc) *SssDoc {
	rvalue := SssDoc{
		Doc:            sd,
		processedShare: make(map[string][]byte),
	}
	return &rvalue
}

const randomStringEntropyBytes = 32

func newFromAgeKeysInternal(recipients [][]byte, identifiers []string, requiredShares int) (*ShareDoc, error) {
	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}
	return generateDocWithSecret(secret, recipients, identifiers, requiredShares)
}

func encryptDataWithPublic(plaintextData []byte, recipientPublic []byte) ([]byte, int, error) {
	publicForBuffer := bytes.Clone(recipientPublic)
	identityBuffer := bytes.NewBuffer(publicForBuffer)

	parsedRecipient, ageParseErr := age.ParseRecipients(identityBuffer)
	if ageParseErr == nil {
		// This is an age key
		ptReader := bytes.NewReader(plaintextData)
		encReader, err := age.EncryptReader(ptReader, parsedRecipient[0])
		if err != nil {
			return nil, KeyTypeAge, err
		}
		encData, err := io.ReadAll(encReader)
		if err != nil {
			return nil, KeyTypeAge, err
		}
		return encData, KeyTypeAge, nil

	}
	// try now with gpg
	publicKey, err := crypto.NewKeyFromArmored(string(recipientPublic))
	if err == nil {
		pgp := crypto.PGP()
		encHandle, err := pgp.Encryption().Recipient(publicKey).New()
		if err != nil {
			return nil, KeyTypePGP, err
		}
		pgpMessage, err := encHandle.Encrypt(plaintextData)
		if err != nil {
			return nil, KeyTypePGP, err
		}
		return pgpMessage.Bytes(), KeyTypePGP, nil

	}
	return nil, KeyTypeUnknown, fmt.Errorf("Unable to parse public key as age or gpg public armored %w", ageParseErr)

}

func generateDocWithSecret(secret []byte, recipients [][]byte, identifiers []string, requiredShares int) (*ShareDoc, error) {
	plaintextShares, err := withSecretGenerateSecretShares(secret, requiredShares, len(recipients))
	if err != nil {
		return nil, err
	}
	var outDoc ShareDoc
	for i, recipient := range recipients {
		plaintextData := plaintextShares[i]
		plaintextFP := sha512.Sum512(plaintextData)
		encData, keyType, err := encryptDataWithPublic(plaintextData, recipient)
		if err != nil {
			return nil, err
		}

		docShare := EncrypedShare{
			Identifier:           identifiers[i],
			EncryptedBlob:        encData,
			PlaintextFingerPrint: plaintextFP[:],
			KeyType:              keyType,
			PublicKey:            recipient,
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

func gpgDecryptSingleShare(share EncrypedShare, armoredPrivate []byte, passphrase []byte) ([]byte, error) {
	privateKey, err := crypto.NewPrivateKeyFromArmored(string(armoredPrivate), passphrase)
	if err != nil {
		return nil, fmt.Errorf("unable to parse armored gpg private key: %w", err)
	}
	pgp := crypto.PGP()
	decHandle, err := pgp.Decryption().DecryptionKey(privateKey).New()
	if err != nil {
		return nil, fmt.Errorf("unable to create gpg decryption handle: %w", err)
	}
	defer decHandle.ClearPrivateParams()
	decrypted, err := decHandle.Decrypt(share.EncryptedBlob, crypto.Bytes)
	if err != nil {
		// TODO, dont do the +%v
		return nil, fmt.Errorf("unable to decrypt %+v %w", share, err)
	}
	return decrypted.Bytes(), nil
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
