# sss-distrib

[![Test](https://github.com/cviecco/sss-distrib/actions/workflows/test.yml/badge.svg)](https://github.com/cviecco/sss-distrib/actions/workflows/test.yml)

Across several projects I have come with the need to share sss (shamir secret sharing) shares with users.
However to do so securely you need to encrypt each share with somthing that only the user can use
to extract the share. In addition since this is usualy part of a bootstrap protocol mTLS is usually
not available and given the prominence of TLS interception points I also want the passing of the share
to the backen to be also encrypted.

Thus there was a need for a library that:
* Given a set public keys and a threshold is able to generate encryped share for each public key.
* This generation will be in the form of a single document so that users only need to worry about keeping 
their private keys. All other information will be kept in the document
* A server


#### Users public Key format
Its 2026 and Johnny cannot encrypt file long term. 
GPG works, but is combersome to use. However has lots of tooling around to make it work
AGE nice cyptography, trusting the filesystem by default is not workable for long term secrets.


 


##
Goal:

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
