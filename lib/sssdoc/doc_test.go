package sssdoc

import (
	"bytes"
	"fmt"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
)

const age_test_key_1 = `# created: 2026-07-16T12:40:31-07:00
# public key: age10hfzhu2hfw6wjn2vjjrqdke3yf5vzk9twwjz505tfv984tdegchs8kuwg6
AGE-SECRET-KEY-16G5QNXFSSUM5HU34JPD5MVR59JNDJGGZSM0ZD60XFU7DHJJSJ6ES62SMGE`

const age_test_key_2 = `# created: 2026-07-16T12:41:31-07:00
# public key: age1q292gkj5jmtqy74rcrym26tj3dz4xjnksuskkzveyw8xk9aamums4p44xj
AGE-SECRET-KEY-1QNV2GWDK3Q2K6MPYZHZ923H3CM24WADC4EYHPMXK04AE30KRU3HS7FA2U9`

const age_test_key_3 = `# created: 2026-07-16T12:42:00-07:00
# public key: age1j3nhn07hllphue7d8n675csazfku8969c8j82g7kkfs0cepcpqfs9qykdz
AGE-SECRET-KEY-1PCL52PZJFSGXHJHTERLS6D08V7DSL58VX5EJYWV0E7GN7CWXYUQQDW9MCW`

// TODO add a pq key for the tests

func TestAgeBase(t *testing.T) {

	recipientsStrings := []string{
		"age10hfzhu2hfw6wjn2vjjrqdke3yf5vzk9twwjz505tfv984tdegchs8kuwg6",
		"age1q292gkj5jmtqy74rcrym26tj3dz4xjnksuskkzveyw8xk9aamums4p44xj",
		"age1j3nhn07hllphue7d8n675csazfku8969c8j82g7kkfs0cepcpqfs9qykdz",
	}
	var recipients [][]byte
	identities := []string{"1", "2", "3"}
	for i, recipient := range recipientsStrings {
		recipients = append(recipients, []byte(recipient))
		identities[i] = fmt.Sprintf("%d", i)
	}

	_, err := newFromAgeKeysInternal(recipients, identities, 2)
	require.NoError(t, err)
}

func TestCreateDecodeRoundTrip(t *testing.T) {
	secret, err := generateSecret()
	require.NoError(t, err)

	recipientsStrings := []string{
		"age10hfzhu2hfw6wjn2vjjrqdke3yf5vzk9twwjz505tfv984tdegchs8kuwg6",
		"age1q292gkj5jmtqy74rcrym26tj3dz4xjnksuskkzveyw8xk9aamums4p44xj",
		"age1j3nhn07hllphue7d8n675csazfku8969c8j82g7kkfs0cepcpqfs9qykdz",
	}
	var recipients [][]byte
	identifiers := []string{"1", "2", "3"}
	for i, recipient := range recipientsStrings {
		recipients = append(recipients, []byte(recipient))
		identifiers[i] = fmt.Sprintf("%d", i)
	}
	shareDoc, err := ageGenerateDocWithSecret(secret, recipients, identifiers, 2)
	require.NoError(t, err)

	identitiesStrings := []string{
		age_test_key_1,
		age_test_key_2,
		age_test_key_3,
	}
	var identities [][]age.Identity
	for _, identStr := range identitiesStrings {
		idReader := bytes.NewReader([]byte(identStr))
		identity, err := age.ParseIdentities(idReader)
		require.NoError(t, err)
		identities = append(identities, identity)
	}

	plaintextSecrets := [][]byte{}
	for i, identity := range identities {
		ptShare, err := ageDecryptSingleShare(shareDoc.Shares[i], identity)
		require.NoError(t, err)
		plaintextSecrets = append(plaintextSecrets, ptShare)
	}

	sssDoc := NewSSSDocFromShareDoc(shareDoc)
	require.NotNil(t, sssDoc)

	found := false
	for _, ptShare := range plaintextSecrets {
		rebuiltSecret, err := sssDoc.ProcessShare(ptShare)
		require.NoError(t, err)
		if rebuiltSecret != nil {
			found = true
			require.Equal(t, rebuiltSecret, secret)
		}
	}
	require.True(t, found)
}
