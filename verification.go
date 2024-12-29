package libjwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

func ValidateSignature(token string, publicKey *rsa.PublicKey) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token")
	}
	signature := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signature))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return errors.New("failed to decode signature from base64")
	}
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sig)
	if err != nil {
		return errors.New("invalid signature")
	}
	return nil
}
