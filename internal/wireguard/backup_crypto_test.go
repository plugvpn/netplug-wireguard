package wireguard

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/scrypt"
)

func TestIsEncryptedBackupEnvelope(t *testing.T) {
	enc, err := EncryptBackupPayload([]byte(`{"version":1}`), "secret")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncryptedBackupEnvelope(enc) {
		t.Fatal("expected encrypted envelope")
	}
	if IsEncryptedBackupEnvelope([]byte(`{"version":1,"peers":[]}`)) {
		t.Fatal("plain backup must not match encrypted envelope")
	}
}

func TestEncryptDecryptBackupRoundTrip(t *testing.T) {
	plain := []byte(`{"version":1,"peers":[]}`)
	password := "test"
	enc, err := EncryptBackupPayload(plain, password)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(enc), "correct-horse") {
		t.Fatal("plaintext password or payload must not appear in encrypted file")
	}
	got, err := DecryptBackupPayload(enc, password)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestDecryptBackupWrongPassword(t *testing.T) {
	enc, err := EncryptBackupPayload([]byte("secret"), "long-password-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptBackupPayload(enc, "long-password-2")
	if err == nil || !strings.Contains(err.Error(), "incorrect backup password") {
		t.Fatalf("expected wrong password error, got %v", err)
	}
}

func TestValidateBackupPassword(t *testing.T) {
	if err := ValidateBackupPassword(""); err != nil {
		t.Fatal("empty password should be allowed")
	}
	if err := ValidateBackupPassword("abc"); err == nil {
		t.Fatal("expected error for password under 4 characters")
	}
	if err := ValidateBackupPassword("abcd"); err != nil {
		t.Fatalf("4 character password should be allowed: %v", err)
	}
}

func TestDecryptBackupLegacyScryptN(t *testing.T) {
	plain := []byte(`{"version":1}`)
	salt := make([]byte, backupSaltLen)
	nonce := make([]byte, backupNonceLen)
	for i := range salt {
		salt[i] = byte(i)
	}
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	legacyN := 32768
	key, err := scrypt.Key([]byte("legacy-pass"), salt, legacyN, backupScryptR, backupScryptP, backupKeyLen)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	env := EncryptedBackupEnvelope{
		Format: encryptedBackupFormat, KDF: backupKDF, Cipher: backupCipher,
		ScryptN: legacyN, ScryptR: backupScryptR, ScryptP: backupScryptP,
		Salt: base64.StdEncoding.EncodeToString(salt),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	raw, _ := json.Marshal(env)
	got, err := DecryptBackupPayload(raw, "legacy-pass")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("legacy decrypt mismatch: %q", got)
	}
}

func TestEncryptedEnvelopeHasNoPlaintextKeys(t *testing.T) {
	plain, _ := json.Marshal(BackupFile{
		Server: BackupServer{PrivateKey: "SUPER_SECRET_KEY"},
	})
	enc, err := EncryptBackupPayload(plain, "backup-pass-phrase")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(enc), "SUPER_SECRET") {
		t.Fatal("private key leaked into encrypted envelope")
	}
}
