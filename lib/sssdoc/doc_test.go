package sssdoc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

const age_test_key_1 = `# created: 2026-07-16T12:40:31-07:00
# public key: age10hfzhu2hfw6wjn2vjjrqdke3yf5vzk9twwjz505tfv984tdegchs8kuwg6
AGE-SECRET-KEY-16G5QNXFSSUM5HU34JPD5MVR59JNDJGGZSM0ZD60XFU7DHJJSJ6ES62SMGE`

const age_test_key_2 = `# created: 2026-07-16T12:41:31-07:00
# public key: age1q292gkj5jmtqy74rcrym26tj3dz4xjnksuskkzveyw8xk9aamums4p44xj
AGE-SECRET-KEY-1QNV2GWDK3Q2K6MPYZHZ923H3CM24WADC4EYHPMXK04AE30KRU3HS7FA2U9`

const aget_test_key_3 = `# created: 2026-07-16T12:42:00-07:00
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
