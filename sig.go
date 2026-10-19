package authz

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

// verifySignature checks a JWS signature with the key the kid named. The
// key's type must match the algorithm: an RSA key never verifies ES256 and
// a P-256 key never verifies RS256.
func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return verifyRSA(alg, k, signed, sig)
	case *ecdsa.PublicKey:
		return verifyES256(alg, k, signed, sig)
	default:
		return fmt.Errorf("unsupported key type %T", key)
	}
}

// verifyRSA checks a PKCS#1 v1.5 signature over the signing input.
func verifyRSA(alg string, key *rsa.PublicKey, signed, sig []byte) error {
	var (
		hash crypto.Hash
		sum  []byte
	)
	switch alg {
	case "RS256":
		h := sha256.Sum256(signed)
		hash, sum = crypto.SHA256, h[:]
	case "RS512":
		h := sha512.Sum512(signed)
		hash, sum = crypto.SHA512, h[:]
	default:
		return fmt.Errorf("algorithm %q does not match an RSA key", alg)
	}
	return rsa.VerifyPKCS1v15(key, hash, sum, sig)
}

// verifyES256 checks a JWS ES256 signature: the raw 64-byte r||s of RFC 7518
// section 3.4, not the ASN.1 DER form crypto/ecdsa produces by default.
func verifyES256(alg string, key *ecdsa.PublicKey, signed, sig []byte) error {
	if alg != "ES256" {
		return fmt.Errorf("algorithm %q does not match an EC key", alg)
	}
	if len(sig) != 64 {
		return fmt.Errorf("ES256 signature is %d bytes, want 64", len(sig))
	}
	h := sha256.Sum256(signed)
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, h[:], r, s) {
		return errors.New("verification error")
	}
	return nil
}
