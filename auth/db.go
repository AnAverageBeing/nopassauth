package auth

type Database interface {
	SaveUser(user *User) error
	GetUserByUsername(username string) (*User, error)
	GetPublicKeyByUsername(username string) (string, error)
	ChangeUserName(oldUsername string, newUsername string) error
	ChangePublicKey(username string, newPublicKet string) error
}
