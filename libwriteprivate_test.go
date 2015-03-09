package main

import (
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

	if string(plaintext) != string(decryptedText) {
		t.Fatal("Decrypted text mismatch.")
	}
}
