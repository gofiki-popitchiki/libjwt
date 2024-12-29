package libjwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func ParsePrivateKey(path string) (privateKey *rsa.PrivateKey, err error) {
	privateKeyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil {
		return nil, errors.New("ошибка декодирования PEM")
	}
	_privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := _privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("закрытый ключ не является RSA ключом")
	}
	return
}

func ParsePublicKey(path string) (publicKey *rsa.PublicKey, err error) {
	publicKeyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	publicKeyBlock, _ := pem.Decode(publicKeyBytes)
	if publicKeyBlock == nil {
		return nil, errors.New("ошибка декодирования PEM")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return pubInterface.(*rsa.PublicKey), err
}
