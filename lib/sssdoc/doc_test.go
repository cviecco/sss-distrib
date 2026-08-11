package sssdoc

import (
	"bytes"
	"fmt"
	"testing"

	"filippo.io/age"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
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

// same as the luggage combination
const testPassphrase = `12345`

// gpg --default-new-key-algo rsa4096 --gen-key
//  gpg  --gen-key

const pgp_sss_test_1 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEanuV0RYJKwYBBAHaRw8BAQdAreB93UG39zZbszjm4qZAPkLIsTZzFiJ0EkZm
4D3h9IX+BwMCTFbqe4/9FiL/SYTNV1eQnYN5VZOIwN3sEPL/fPkTB/pf0nm07Pol
SLo4VPYiLXIcR4dt1KSmx/tHEgM4aQVrbTWsSV8fvlZFFEM/MGC5KrQrc3NzX3Rl
c3Rfa2V5XzEgPHNzc190ZXN0X2tleV8xQGV4YW1wbGUuY29tPoi1BBMWCgBdFiEE
75wm5LSQ1mcsE+kP6BosHkovdwEFAmp7ldEbFIAAAAAABAAObWFudTIsMi41KzEu
MTIsMCwzAhsDBQkFo5qABQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEOga
LB5KL3cB4KIBANir8Gw1Y8E1xL2TAtIuHEatoSY2GczBa/5m/IOxHo7wAQCLgoDl
sQvk/mK3Wzad4gbhAQboy3pqngwxvAazpDvnApyLBGp7ldESCisGAQQBl1UBBQEB
B0BYOaOjpP3NqtQAaI9FdVvRYrR1xiZ/HmovJfibrq/8JgMBCAf+BwMCKVb6Rp6U
/k3/w9qhxMHuD71aglHVJrryJXjnIgnbm4g+vMewjXnVkTdRpsDuTJyEx/8hUPqi
2QtOGRK6Xib96W1T88RNxoGtbkcOeUmE7YiaBBgWCgBCFiEE75wm5LSQ1mcsE+kP
6BosHkovdwEFAmp7ldEbFIAAAAAABAAObWFudTIsMi41KzEuMTIsMCwzAhsMBQkF
o5qAAAoJEOgaLB5KL3cBniMBALEmun8x14Vi8wVNaxlzxXrhsqoCkvjO7xzE0fPv
2Wd3AQDr7IcJYSptY4uDFiu7pFr2NkYpHZ6ttZ8B2XphCIGECQ==
=2wd5
-----END PGP PRIVATE KEY BLOCK-----`

// gpg --export-secret-key -a  sss_test_2
const pgp_sss_test_2 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEamfT4RYJKwYBBAHaRw8BAQdAj+jNv+w5J6OM8i2M2JZHh787jMil7OfeCq1j
yobr+OH+BwMCDCuDgwcHSbv/pfaQmhOtp4+pRUdaTeB5KELb6KAmOLgqTx4VvAx3
99pUljrlboXCb+jGM0MDkoybAdLqTtMFKL2dhoWqU8VC0L1XAi2FWrQjc3NzX3Rl
c3RfMiA8c3NzX3Rlc3RfMUBleGFtcGxlLmNvbT6ItQQTFgoAXRYhBLUf2KrSUb+O
F25la9vnt+fXMdgxBQJqZ9PhGxSAAAAAAAQADm1hbnUyLDIuNSsxLjEyLDAsMwIb
AwUJBaOagAULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRDb57fn1zHYMd/M
AQDfTLb700FCGPNO7n60cLwXWcE+4XABMz4QLEPmJHEDRQEAhS36r70Ow0PMqVj5
P5PMO5RTLWhKHkSFmWrPj1lyZgmciwRqZ9PhEgorBgEEAZdVAQUBAQdAgfE0QFrK
yse46ntFzqTQdmDqFMFDarA0YkfqoYpuPS0DAQgH/gcDAnB/dgWKhuAQ/3T458wh
E84ZySG2JU8to/9o1Mh8kfeuEejhY79leEwuidCl4f3VHIWE2vaFv34AGJG8lSE4
WfYZVFGLs+nYpPOeDTU6evWImgQYFgoAQhYhBLUf2KrSUb+OF25la9vnt+fXMdgx
BQJqZ9PhGxSAAAAAAAQADm1hbnUyLDIuNSsxLjEyLDAsMwIbDAUJBaOagAAKCRDb
57fn1zHYMUKDAQCmjHVc4d5XCzKecMKi8mTIFuq0BScRAEztRfWsr/HizwD/fAFs
vaLzRF3hVUCOHOhpFt3+f4M5YKwzfUoONqKCvQE=
=d6S4
-----END PGP PRIVATE KEY BLOCK-----`
const pgp_sss_test_3 = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEamkfRRYJKwYBBAHaRw8BAQdARP0fLLEyjksSpfkPZM6KGSzwu5+s29BOl5UG
cQaGxyf+BwMCrODo/hdEjNv/8HvHQzPeN2ZSs6UduOQiLvaaV4GaIBmtHMQMxXxs
YCNTD//Cw1O7i1wYnMc2Sonyp5aGxER7cJS26/npgnnuWOsOD8nyRrQjc3NzX3Rl
c3RfMyA8c3NzX3Rlc3RfM0BleGFtcGxlLmNvbT6ItQQTFgoAXRYhBKyhcMUDZHUk
5tYi7IApUB6WhN/VBQJqaR9FGxSAAAAAAAQADm1hbnUyLDIuNSsxLjEyLDAsMwIb
AwUJBaOagAULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRCAKVAeloTf1f4Q
AP9T/0t4+PwLTZghrc1wuruUlDByrGYa3QCxoPRVd8RMrAD/e7evWZxjnzii6saB
tfrlUyYJs/pWlUDPdbgSU60GaAGciwRqaR9FEgorBgEEAZdVAQUBAQdAOm0o5uBS
9e/9OMQ1CtbGcAAbtFxtkZyozsV/rXa1unMDAQgH/gcDAuwWTHiIVs9c/2YpD6C1
1QZCDFiRWYAdjsGh4CSTkiFvEpLFUq8eNSS2yVIR7zUqFCdyGhGppS/XGil+aRsS
mGTL65x6rptxHlymmDYr8xaImgQYFgoAQhYhBKyhcMUDZHUk5tYi7IApUB6WhN/V
BQJqaR9FGxSAAAAAAAQADm1hbnUyLDIuNSsxLjEyLDAsMwIbDAUJBaOagAAKCRCA
KVAeloTf1ayDAQD7fUBRXQMgGXlvu8eWCWBlwArYvBLzt94XjXSZBjmEAAEAk1eP
TwwRRi5pixdoq0c/mMUTS+fIB2Mxfl1LnajZcgg=
=uQ8l
-----END PGP PRIVATE KEY BLOCK-----`

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

func TestGpgCreateDecodeRoundTrip(t *testing.T) {
	secret, err := generateSecret()
	require.NoError(t, err)

	identifiers := []string{"1", "2", "3"}
	armoredPrivate := []string{pgp_sss_test_1,
		pgp_sss_test_2, pgp_sss_test_3}
	var recipients [][]byte
	var privateKeys []*crypto.Key

	for _, armored := range armoredPrivate {
		privateKey, err := crypto.NewPrivateKeyFromArmored(armored, []byte(testPassphrase))
		require.NoError(t, err)
		privateKeys = append(privateKeys, privateKey)
		publicKey, err := privateKey.ToPublic()
		require.NoError(t, err)
		armoredPub, err := publicKey.GetArmoredPublicKey()
		require.NoError(t, err)
		recipients = append(recipients, []byte(armoredPub))

	}

	shareDoc, err := gpgGenerateDocWithSecret(secret, recipients, identifiers, 2)
	require.NoError(t, err)

	plaintextSecrets := [][]byte{}
	for i, armored := range armoredPrivate {
		ptShare, err := gpgDecryptSingleShare(shareDoc.Shares[i], []byte(armored), []byte(testPassphrase))
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
