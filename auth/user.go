package auth

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

type User struct {
	// min 3 char max 16
	// only alphanumerical and '_' (must not end of start with '_')
	username string

	// rsa public key in pem format
	publicKey string
}

func (u *User) GetUsername() *string {
	return &u.username
}

func (u *User) SetUsername(newName string) error {
	err := validateUsername(newName)
	if err != nil {
		return err
	}
	u.username = newName
	return nil
}

func (u *User) GetPublicKey() *string {
	return &u.publicKey
}

func (u *User) SetPublicKey(newKey string) error {
	err := validatePEMPublicKey(newKey)
	if err != nil {
		return err
	}
	u.publicKey = newKey
	return nil
}

func NewUser(username string, publicKey string) (*User, error) {

	if err := validateUsername(username); err != nil {
		return nil, err
	}

	if err := validatePEMPublicKey(publicKey); err != nil {
		return nil, err
	}

	return &User{
		username:  username,
		publicKey: publicKey,
	}, nil
}

func validateUsername(username string) error {
	nameLength := len(username)

	if nameLength < 3 || nameLength > 16 {
		return fmt.Errorf("username length must be between 3 and 16 characters, but got %d characters", nameLength)
	}

	for i, c := range username {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && (c != '_') {
			return fmt.Errorf("invalid character at position %d in username", i)
		}
	}

	if username[0] == '_' {
		return errors.New("username cannot start with '_'")
	}

	if username[nameLength-1] == '_' {
		return errors.New("username cannot end with '_'")
	}

	return nil
}

func validatePEMPublicKey(publicKey string) error {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return errors.New("invalid PEM public key")
	}

	_, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse PEM public key: %w", err)
	}

	return nil
}
