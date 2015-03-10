package writeprivate

import (
	"bytes"
	"fmt"
	"testing"
)

func TestEncDec(t *testing.T) {
	passphrase := "hello"
	plaintext := "this is my secret message™. 😄"

	fmt.Println(plaintext)

	// Encrypt the data
	ciphertext, err := Encrypt(passphrase, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%s\n", ciphertext)

	// Decrypt the data
	decryptedText, err := Decrypt(passphrase, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(decryptedText))

	if !bytes.Equal([]byte(plaintext), decryptedText) {
		t.Errorf("Plaintext mismatch: got %x vs %x", plaintext, decryptedText)
	}
}
