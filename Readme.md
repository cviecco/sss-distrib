# sss-distrib

[![Test](https://github.com/cviecco/sss-distrib/actions/workflows/test.yml/badge.svg)](https://github.com/cviecco/sss-distrib/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/cviecco/sss-distrib/graph/badge.svg?token=E0Z157E0PW)](https://codecov.io/gh/cviecco/sss-distrib)

Across several projects I have come with the need to share a secret using sss (shamir secret sharing) shares with users.
However to do so securely you need to encrypt each share with somthing that only the user can use
to extract the share. In addition since this is usualy part of a bootstrap protocol mTLS is usually
not available and given the prominence of TLS interception points I also want the passing of the share
to the backen to be also encrypted.

Thus there was a need for a library that:
* Given a set public keys and a threshold is able to generate encryped share for each public key.
* This generation will be in the form of a single document so that users only need to worry about keeping 
their private keys. All other information will be kept in the document
* A server that is able to do a pseudo session with the injectors so that the secret cannot be in plaintext
(so that It cannot be logged even by accident) and that prevents an attacker from replaying a message.
* a server session that is time independent (as during boostrap time can we way off between server and client)



#### Users public Key format
Its 2026 and Johnny cannot encrypt file long term. 
GPG works, but is combersome to use. However has lots of tooling around to make it work
AGE nice cyptography, trusting the filesystem by default is not workable for long term secrets.

### Attacker model
This project assumes a passive TLS intereptor environment. Where the protected streams are NOT end
to end between client and server (DLP software, TLS terminating load balancers). The system should
prevent this attacker from being able to either obtain any of the shares or be able to replay the share
message to unseal another server.

This library currently does NOT prevent an active attacker that modifies messages in transit.


#### Dependecncies
We have tried to minimize the number of non native libraries. To reduce the risk
of supply chaing issues.

The library has 4 package dependencies:
1. github.com/lydianpay/shamir-secret-sharing for the shamir secret sharing implementation
2. filippo.io/age for age operations 
3. github.com/ProtonMail/gopenpgp/v3 for gpg operations 
4. golang.org/x/crypto for the hkdf implementaiton for the replay prevention.

The cli command adds dependencies on:
1. github.com/alecthomas/kong for cli parsing
2. golang.org/x/term for password/passphrase reading

Testing adds:
1. github.com/stretchr/testify for simpler tests
2. github.com/neilotoole/slogt/v2 for slog mocking 


#### Goals:


1. Given a set of public gpg public keys(M), and a number (N) splits
   1. Generate a new 256 bit secret
   2. Split the secret into M/N using sss 
   3. Compute fingerprint for each share
   3. Encrypt the shares into gpg secrets 
   4. Generate new JSON doc with array of names/encrypted shares/fingerprints
  


Server handlers:
1. Share status +
   1. Get encryped user form (takes username)
   2. Paste cleartext share.
3. return full doc
   2. Return json pgp/sss doc.
3. Return user encrypted share. 
4. Share combiner handler
   1. takes claimed secret
   2. Verifies fingerprint
   3. Add to internal map
      If threshold passes then try to decrypt secret.


Cient: none. 
