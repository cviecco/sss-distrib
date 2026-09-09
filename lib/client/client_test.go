package client

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const testPassphrase = "12345" // same as my lugggage

func TestSimpleFileRoundTripAge(t *testing.T) {
	dir, err := os.MkdirTemp("", "example")
	require.NoError(t, err)

	defer os.RemoveAll(dir) // clean up

	filename := filepath.Join(dir, "tmpfile")

	sc1, err := NewAgeKeyWithPassPhrase(filename, testPassphrase, "http://example.com")
	require.NoError(t, err)
	require.NotNil(t, sc1)

	filedata, err := os.ReadFile(filename)
	require.NoError(t, err)
	fmt.Printf("filedata=%s", string(filedata))

	sc2, err := LoadAgeKeyWithPassPhrase(filename, testPassphrase)
	require.NoError(t, err)
	require.NotNil(t, sc2)

	// PrivateKeys should match
	require.Equal(t, sc1.ptPrivateKey, sc2.ptPrivateKey)

}
