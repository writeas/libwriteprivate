package writeprivate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"strings"
)

const (
	keyLen         = 32
	saltLen        = 64
	iterationCount = 10000
	delimiter      = '%'
)

func Encrypt(passphrase, plaintext string) ([]byte, error) {
	// Generate the salt
	s := make([]byte, saltLen)
	_, err := rand.Read(s)
	if err != nil {
		return nil, err
	}

	// Derive key from passphrase
	k := pbkdf2.Key([]byte(passphrase), s, iterationCount, keyLen, sha256.New)

	// Encrypt plaintext with AES-GCM
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	ns := gcm.NonceSize()
	nonce := make([]byte, ns)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Build text output in the format:
	// NonceCiphertextDelimiterSalt
	outtext := encodeBase64(append(nonce, ciphertext...))
	outtext = append(outtext, delimiter)
	outtext = append(outtext, encodeBase64(s)...)

	return outtext, nil
}

func Decrypt(passphrase string, ciphertext []byte) ([]byte, error) {
	// Get ciphertext and salt fields
	fields := strings.Split(string(ciphertext), string(delimiter))
	ciphertext = decodeBase64(fields[0])
	s := decodeBase64(fields[1])

	// Derive key from passphrase and stored salt
	k := pbkdf2.Key([]byte(passphrase), s, iterationCount, keyLen, sha256.New)

	// Decrypt ciphertext
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ns := gcm.NonceSize()

	// Validate data
	if len(ciphertext) < ns {
		return nil, errors.New("Ciphertext is too short")
	}

	nonce := ciphertext[:ns]
	ciphertext = ciphertext[ns:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func encodeBase64(message []byte) []byte {
	base64Text := make([]byte, base64.StdEncoding.EncodedLen(len(message)))
	base64.StdEncoding.Encode(base64Text, message)
	return base64Text
}

func decodeBase64(message string) []byte {
	base64Text := make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	l, _ := base64.StdEncoding.Decode(base64Text, []byte(message))
	return base64Text[:l]
}
