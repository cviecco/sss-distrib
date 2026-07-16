package sssdoc

import (
	"crypto/rand"
	"fmt"

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

func generateAndSplitSecret(threshold int, numshares int) ([][]byte, error) {

	if numshares < 2 || numshares > 32 {
		return nil, fmt.Errorf("invalid number of shares")
	}
	if threshold >= numshares || threshold < 2 {
		return nil, fmt.Errorf("invalid number of combiners")
	}

	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}

	return withSecretGenerateAndSplitSecret(secret, threshold, numshares)
}

func withSecretGenerateAndSplitSecret(secret []byte, threshold int, numshares int) ([][]byte, error) {
	return shamir.GenerateShares(secret, numshares, threshold)
}

func combineSecret(shares [][]byte) ([]byte, error) {
	return shamir.Reconstruct(shares)
}
