package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"io"
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

	// Encrypt plaintext
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	// Include IV at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	ciphertext = encodeBase64(ciphertext)
	ciphertext = append(ciphertext, delimiter)
	ciphertext = append(ciphertext, encodeBase64(s)...)

	return ciphertext, nil
}

func Decrypt(passphrase string, ciphertext []byte) ([]byte, error) {
	// Get fields
	fields := strings.Split(string(ciphertext), string(delimiter))
	ciphertext = decodeBase64(fields[0])
	s := decodeBase64(fields[1])

	// Validate data
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("Ciphertext is too short")
	}

	// Derive key from passphrase and stored salt
	k := pbkdf2.Key([]byte(passphrase), s, iterationCount, keyLen, sha256.New)

	// Decrypt ciphertext
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	plaintext := ciphertext[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(plaintext, plaintext)
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
