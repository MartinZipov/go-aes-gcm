package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
)

func main() {
	data := []byte("Hello, GCM!")

	// Generate random key.
	key, err := generateRandomBytes(32)
	if err != nil {
		log.Fatal(err)
	}

	// Generate random nonce.
	nonce, err := generateRandomBytes(12)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt the data
	ciphertext, err := aesGCMEncryp(key, nonce, data)
	if err != nil {
		log.Fatal(err)
	}
	// Decrypt the data
	plaintext, err := aesGCMDecrypt(key, nonce, ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(plaintext) == string(data))
}

func aesGCMEncryp(key, nonce, data []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aead.Seal(nil, nonce, data, nil), nil
}

func aesGCMDecrypt(key, nonce, ciphertext []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err = aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func generateRandomBytes(size int) ([]byte, error) {
	rb := make([]byte, size)
	_, err := rand.Read(rb)
	if err != nil {
		return nil, err
	}

	return rb, nil
}
