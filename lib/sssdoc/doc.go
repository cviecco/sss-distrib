package sssdoc

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
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
	Doc            *ShareDoc
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

func NewSSSDocFromShareDoc(sd *ShareDoc) *SssDoc {
	rvalue := SssDoc{
		Doc:            sd,
		processedShare: make(map[string][]byte),
	}
	return &rvalue
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

// gpgGenerateDocWithSecret splits secret into shares and encrypts each share
// to the corresponding recipient in recipients, where each entry is an
// armored GPG/PGP public key. Encryption follows the "Encrypt / Decrypt with
// PGP keys" recipe from the gopenpgp README: an armored public key is loaded
// with crypto.NewKeyFromArmored, an encryption handle is built for that
// recipient via pgp.Encryption().Recipient(...).New(), and the share is
// encrypted with that handle's Encrypt method.
func gpgGenerateDocWithSecret(secret []byte, recipients [][]byte, identifiers []string, requiredShares int) (*ShareDoc, error) {
	plaintextShares, err := withSecretGenerateSecretShares(secret, requiredShares, len(recipients))
	if err != nil {
		return nil, err
	}
	pgp := crypto.PGP()
	var outDoc ShareDoc
	for i, recipient := range recipients {
		publicKey, err := crypto.NewKeyFromArmored(string(recipient))
		if err != nil {
			return nil, fmt.Errorf("unable to parse armored gpg public key: %w", err)
		}
		encHandle, err := pgp.Encryption().Recipient(publicKey).New()
		if err != nil {
			return nil, fmt.Errorf("unable to create gpg encryption handle: %w", err)
		}
		plaintextData := plaintextShares[i]
		plaintextFP := sha512.Sum512(plaintextData)
		pgpMessage, err := encHandle.Encrypt(plaintextData)
		if err != nil {
			return nil, fmt.Errorf("unable to encrypt share: %w", err)
		}
		encData := pgpMessage.Bytes()

		docShare := EncrypedShare{
			Identifier:           identifiers[i],
			EncryptedBlob:        encData,
			PlaintextFingerPrint: plaintextFP[:],
			KeyType:              KeyTypePGP,
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

// gpgDecryptSingleShare decrypts share.EncryptedBlob using identity, an
// armored GPG/PGP private key (unlocked, i.e. no passphrase). It follows the
// "Encrypt / Decrypt with PGP keys" recipe from the gopenpgp README: the
// armored private key is loaded with crypto.NewPrivateKeyFromArmored, a
// decryption handle is built via pgp.Decryption().DecryptionKey(...).New(),
// and the blob is decrypted with that handle's Decrypt method.
func gpgDecryptSingleShare(share EncrypedShare, identity []byte) ([]byte, error) {
	privateKey, err := crypto.NewPrivateKeyFromArmored(string(identity), nil)
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
