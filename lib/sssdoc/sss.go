package sssdoc

import (
	"crypto/rand"

	shamir "github.com/lydianpay/shamir-secret-sharing"
)

const secretSizeBytes = 32

func generateSecret() ([]byte, error) {
	rb := make([]byte, secretSizeBytes)
	_, err := rand.Read(rb)
	if err != nil {
		return nil, err
	}
	return rb[:], nil

}

func withSecretGenerateSecretShares(secret []byte, threshold int, numshares int) ([][]byte, error) {
	return shamir.GenerateShares(secret, numshares, threshold)
}

func combineSecret(shares [][]byte) ([]byte, error) {
	return shamir.Reconstruct(shares)
}
