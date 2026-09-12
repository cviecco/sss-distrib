package sssdoc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewReplayProtecor(t *testing.T) {
	rp, err := NewReplayProtector()
	require.NoError(t, err)
	require.NotNil(t, rp)
	// Now on the default case you will get the
	// same valuue for a while, ensure that is true
	var prev []byte
	for i := 0; i < 5; i++ {
		current, err := rp.GetProtectorBytes()
		require.NoError(t, err)
		require.NotNil(t, rp)
		if prev != nil {
			require.Equal(t, prev, current)
		}
		prev = current
	}
	require.True(t, len(rp.replayNonceQueue) == 1)
	require.True(t, rp.CheckReplayExists(prev))
	require.True(t, len(rp.replayNonceQueue) == 1)

}

func TestGetProtectorBytes(t *testing.T) {
	rp, err := NewReplayProtector()
	require.NoError(t, err)
	require.NotNil(t, rp)

	rp.rpDuration = time.Millisecond * 100
	var protectors [][]byte
	for i := 0; i < 5; i++ {
		prot, err := rp.GetProtectorBytes()
		require.NoError(t, err)
		require.NotNil(t, rp)
		protectors = append(protectors, prot)
		time.Sleep(time.Millisecond * 50)
	}
	for _, rpval := range protectors {
		require.True(t, rp.CheckReplayExists(rpval))
	}
	require.NotEqual(t, protectors[0], protectors[len(protectors)-1])
	rp.maxAge = time.Millisecond * 200
	require.False(t, rp.CheckReplayExists(protectors[0]))
	require.True(t, rp.CheckReplayExists(protectors[len(protectors)-1]))

}
