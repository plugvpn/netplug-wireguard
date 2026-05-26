package wireguard

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	encryptedBackupFormat = "netplug-encrypted-backup-v1"
	backupKDF             = "scrypt"
	backupCipher          = "aes-256-gcm"

	backupScryptN = 16384
	backupScryptR = 8
	backupScryptP = 1

	backupSaltLen  = 32
	backupNonceLen = 12
	backupKeyLen   = 32

	backupPasswordMinLen = 4
	backupPasswordMaxLen = 256
)

// EncryptedBackupEnvelope is the on-disk format. Only ciphertext and KDF metadata
// are stored; secrets never appear in plaintext in the file.
type EncryptedBackupEnvelope struct {
	Format     string `json:"format"`
	KDF        string `json:"kdf"`
	Cipher     string `json:"cipher"`
	ScryptN    int    `json:"scryptN"`
	ScryptR    int    `json:"scryptR"`
	ScryptP    int    `json:"scryptP"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func ValidateBackupPassword(password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return nil
	}
	if len(password) < backupPasswordMinLen {
		return fmt.Errorf("backup password must be at least %d characters", backupPasswordMinLen)
	}
	if len(password) > backupPasswordMaxLen {
		return fmt.Errorf("backup password must be at most %d characters", backupPasswordMaxLen)
	}
	return nil
}

func IsEncryptedBackupEnvelope(data []byte) bool {
	var env struct {
		Format     string `json:"format"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return false
	}
	return env.Format == encryptedBackupFormat && strings.TrimSpace(env.Ciphertext) != ""
}

func EncryptBackupPayload(plaintext []byte, password string) ([]byte, error) {
	password = strings.TrimSpace(password)
	if password == "" {
		return nil, errors.New("backup password is required for encryption")
	}
	if err := ValidateBackupPassword(password); err != nil {
		return nil, err
	}
	salt := make([]byte, backupSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key, err := scrypt.Key([]byte(password), salt, backupScryptN, backupScryptR, backupScryptP, backupKeyLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, backupNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	env := EncryptedBackupEnvelope{
		Format:     encryptedBackupFormat,
		KDF:        backupKDF,
		Cipher:     backupCipher,
		ScryptN:    backupScryptN,
		ScryptR:    backupScryptR,
		ScryptP:    backupScryptP,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	return json.MarshalIndent(env, "", "  ")
}

func DecryptBackupPayload(data []byte, password string) ([]byte, error) {
	password = strings.TrimSpace(password)
	if password == "" {
		return nil, errors.New("backup password is required for encrypted backups")
	}
	if err := ValidateBackupPassword(password); err != nil {
		return nil, err
	}
	var env EncryptedBackupEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, errors.New("invalid encrypted backup file")
	}
	if env.Format != encryptedBackupFormat {
		return nil, errors.New("not an encrypted backup file")
	}
	if env.KDF != backupKDF || env.Cipher != backupCipher {
		return nil, errors.New("unsupported backup encryption parameters")
	}
	if env.ScryptN < 8192 || env.ScryptR < 1 || env.ScryptP < 1 {
		return nil, errors.New("backup was created with incompatible encryption settings")
	}

	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) == 0 {
		return nil, errors.New("invalid backup salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != backupNonceLen {
		return nil, errors.New("invalid backup nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil || len(ciphertext) == 0 {
		return nil, errors.New("invalid backup ciphertext")
	}

	key, err := scrypt.Key([]byte(password), salt, env.ScryptN, env.ScryptR, env.ScryptP, backupKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("incorrect backup password or corrupted backup file")
	}
	return plaintext, nil
}
