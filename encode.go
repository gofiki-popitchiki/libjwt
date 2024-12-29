package libjwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func encodeToken(header, payload map[string]interface{}) (encodedData string, err error) {
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	fmt.Printf("%q\t%q\n", headerBytes, payloadBytes)

	encodedBody := base64.RawURLEncoding.EncodeToString(payloadBytes)
	encodedHeaders := base64.RawURLEncoding.EncodeToString(headerBytes)
	fmt.Printf("\n%q\t%q\n\n", encodedHeaders, encodedBody)

	encodedData = encodedHeaders + "." + encodedBody
	
	return encodedData, nil
}

func encodeSignature(data string, privateKey *rsa.PrivateKey) (string, error) {

	hashed := sha256.Sum256([]byte(data))

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	signatureString := base64.RawURLEncoding.EncodeToString(signature)

	// signatureString = strings.TrimRight(signatureString, "=")

	jwt := (data + "." + signatureString)

	return jwt, nil

}

func Encode(header, payload map[string]interface{}, privateKey *rsa.PrivateKey) (string, error) {
	data, err := encodeToken(header, payload)
	if err != nil {
		return "", err
	}
	token, err := encodeSignature(data, privateKey)
	if err != nil {
		return "", err
	}
	return token, nil
}