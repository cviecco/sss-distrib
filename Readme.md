
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
