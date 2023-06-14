package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func EncryptWithPublicKey(data []byte, publicKey string) ([]byte, error) {
	// Decode the PEM-encoded public key
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	// Parse the ASN.1 encoded public key
	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Type assert the public key to the RSA public key type
	rsaPublicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to cast public key to RSA public key type")
	}

	// Encrypt the data using the public key
	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, data)
	if err != nil {
		return nil, err
	}

	return encryptedData, nil
}
