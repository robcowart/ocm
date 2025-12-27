// Package crypto provides cryptographic operations for OCM certificate management.
// It includes AES-256-GCM encryption for secure key storage, X.509 certificate
// generation and signing (RSA and ECDSA), CA operations (self-signed and imported),
// and certificate export in multiple formats (PEM and PKCS#12/PFX).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// EncryptPrivateKey encrypts a private key using AES-256-GCM
func EncryptPrivateKey(plaintext []byte, masterKey []byte, associatedData string) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext with associated data
	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(associatedData))

	// Prepend nonce to ciphertext
	result := append(nonce, ciphertext...)
	return result, nil
}

// DecryptPrivateKey decrypts a private key using AES-256-GCM
func DecryptPrivateKey(encrypted []byte, masterKey []byte, associatedData string) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(associatedData))
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// GenerateMasterKey generates a new 32-byte (256-bit) master key
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}
	return key, nil
}
