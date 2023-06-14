package database

import (
	"database/sql"
	"errors"

	"github.com/AnAverageBeing/nopassauth/auth"
	_ "github.com/mattn/go-sqlite3"
)

type SQLiteDB struct {
	db *sql.DB
}

func NewSQLiteDB(dbPath string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Create the users table if it doesn't exist
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		public_key TEXT
	);`)
	if err != nil {
		return nil, err
	}

	return &SQLiteDB{
		db: db,
	}, nil
}

func (sdb *SQLiteDB) SaveUser(user *auth.User) error {
	// Check if the username already exists
	_, err := sdb.GetUserByUsername(*user.GetUsername())
	if err == nil {
		return errors.New("username already exists")
	}

	// Insert the user into the database
	_, err = sdb.db.Exec("INSERT INTO users (username, public_key) VALUES (?, ?);", user.GetUsername(), user.GetPublicKey())
	return err
}

func (sdb *SQLiteDB) GetUserByUsername(username string) (*auth.User, error) {
	row := sdb.db.QueryRow("SELECT username, public_key FROM users WHERE username = ?;", username)

	var u auth.User
	err := row.Scan(u.GetUsername(), u.GetPublicKey())
	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, err
	}

	return &u, nil
}

func (sdb *SQLiteDB) GetPublicKeyByUsername(username string) (string, error) {
	row := sdb.db.QueryRow("SELECT public_key FROM users WHERE username = ?;", username)

	var publicKey string
	err := row.Scan(&publicKey)
	if err == sql.ErrNoRows {
		return "", errors.New("user not found")
	}
	if err != nil {
		return "", err
	}

	return publicKey, nil
}

func (sdb *SQLiteDB) ChangeUserName(oldUsername string, newUsername string) error {
	// Check if the new username already exists
	_, err := sdb.GetUserByUsername(newUsername)
	if err == nil {
		return errors.New("new username already exists")
	}

	// Update the username in the database
	_, err = sdb.db.Exec("UPDATE users SET username = ? WHERE username = ?;", newUsername, oldUsername)
	return err
}

func (sdb *SQLiteDB) ChangePublicKey(username string, newPublicKey string) error {
	_, err := sdb.db.Exec("UPDATE users SET public_key = ? WHERE username = ?;", newPublicKey, username)
	return err
}
