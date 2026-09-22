package main

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateAgeKeyCommand(t *testing.T) {
	tempDir := t.TempDir()
	outfile := filepath.Join(tempDir, "outfile")
	command := GenNewEncAgeKey{
		OutputPath: outfile,
		passphrase: "12345",
	}
	context := Context{}
	err := command.Run(&context)
	require.NoError(t, err)

}
