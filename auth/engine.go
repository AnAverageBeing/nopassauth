package auth

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

type AuthEngine struct {
	jwtSecret []byte
	db        Database
}

func NewAuthEngine(jwtSecret []byte, db Database) (*AuthEngine, error) {
	return &AuthEngine{
		jwtSecret: jwtSecret,
		db:        db,
	}, nil
}

func (ae *AuthEngine) RegisterUser(username string, publicKey string) (string, error) {
	_, err := ae.db.GetUserByUsername(username)
	if err == nil {
		return "", errors.New("username already exists")
	}

	user, err := NewUser(username, publicKey)
	if err != nil {
		return "", err
	}

	// Generate and sign the JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = jwt.MapClaims{
		"username": user.GetUsername(),
	}

	// Sign the token with the JWT secret
	tokenString, err := token.SignedString(ae.jwtSecret)
	if err != nil {
		return "", err
	}

	// Encrypt the token with the user's public key
	encryptedToken, err := EncryptWithPublicKey([]byte(tokenString), user.GetPublicKey())
	if err != nil {
		return "", err
	}

	return string(encryptedToken), ae.db.SaveUser(user)
}

func (ae *AuthEngine) LoginUser(username string) (string, error) {
	user, err := ae.db.GetUserByUsername(username)
	if err != nil {
		return "", errors.New("username not found")
	}

	// Generate and sign the JWT token
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims = jwt.MapClaims{
		"username": user.GetUsername(),
	}

	// Sign the token with the JWT secret
	tokenString, err := token.SignedString(ae.jwtSecret)
	if err != nil {
		return "", err
	}

	// Encrypt the token with the user's public key
	encryptedToken, err := EncryptWithPublicKey([]byte(tokenString), user.GetPublicKey())
	if err != nil {
		return "", err
	}

	return string(encryptedToken), nil
}
