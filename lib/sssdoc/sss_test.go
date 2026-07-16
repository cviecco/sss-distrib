package sssdoc

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBaseSSS(t *testing.T) {
	secret, err := generateSecret()
	require.NoError(t, err)

	for threshold := 2; threshold < 4; threshold++ {
		//threshold := 2
		for numshares := threshold + 1; numshares < threshold+4; numshares++ {
			//numshares := 4
			shares, err := withSecretGenerateAndSplitSecret(secret, threshold, numshares)
			require.NoError(t, err)
			// TODO: make a loop ensuring it actually is able to combine
			sharesToCombine := shares[1:]
			computedSecret, err := combineSecret(sharesToCombine)
			require.NoError(t, err)
			require.True(t, bytes.Equal(secret, computedSecret))
			// TODO: make combiner missing 2 shares.
		}
	}
}
