package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateMasterKey(t *testing.T) {
	t.Run("Generate master key successfully", func(t *testing.T) {
		key, err := GenerateMasterKey()
		require.NoError(t, err)
		assert.Len(t, key, 32, "Master key should be 32 bytes (256 bits)")
	})

	t.Run("Generate unique keys", func(t *testing.T) {
		key1, err := GenerateMasterKey()
		require.NoError(t, err)

		key2, err := GenerateMasterKey()
		require.NoError(t, err)

		assert.NotEqual(t, key1, key2, "Each generated key should be unique")
	})
}

func TestEncryptDecryptPrivateKey(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	require.NoError(t, err)

	t.Run("Encrypt and decrypt successfully", func(t *testing.T) {
		plaintext := []byte("secret private key data")
		associatedData := "test-certificate-id"

		encrypted, err := EncryptPrivateKey(plaintext, masterKey, associatedData)
		require.NoError(t, err)
		assert.NotNil(t, encrypted)
		assert.Greater(t, len(encrypted), len(plaintext), "Encrypted data should be larger than plaintext")

		decrypted, err := DecryptPrivateKey(encrypted, masterKey, associatedData)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted, "Decrypted data should match original plaintext")
	})

	t.Run("Encrypt produces different ciphertext each time", func(t *testing.T) {
		plaintext := []byte("same plaintext")
		associatedData := "test-id"

		encrypted1, err := EncryptPrivateKey(plaintext, masterKey, associatedData)
		require.NoError(t, err)

		encrypted2, err := EncryptPrivateKey(plaintext, masterKey, associatedData)
		require.NoError(t, err)

		assert.NotEqual(t, encrypted1, encrypted2, "Each encryption should produce different ciphertext due to random nonce")
	})

	t.Run("Decrypt with wrong master key fails", func(t *testing.T) {
		plaintext := []byte("secret data")
		associatedData := "test-id"

		encrypted, err := EncryptPrivateKey(plaintext, masterKey, associatedData)
		require.NoError(t, err)

		wrongKey, err := GenerateMasterKey()
		require.NoError(t, err)

		_, err = DecryptPrivateKey(encrypted, wrongKey, associatedData)
		assert.Error(t, err, "Decryption with wrong key should fail")
	})

	t.Run("Decrypt with wrong associated data fails", func(t *testing.T) {
		plaintext := []byte("secret data")
		associatedData := "correct-id"

		encrypted, err := EncryptPrivateKey(plaintext, masterKey, associatedData)
		require.NoError(t, err)

		_, err = DecryptPrivateKey(encrypted, masterKey, "wrong-id")
		assert.Error(t, err, "Decryption with wrong associated data should fail")
	})

	t.Run("Decrypt empty data fails", func(t *testing.T) {
		_, err := DecryptPrivateKey([]byte{}, masterKey, "test-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ciphertext too short")
	})

	t.Run("Decrypt truncated data fails", func(t *testing.T) {
		plaintext := []byte("secret data")
		associatedData := "test-id"

		encrypted, err := EncryptPrivateKey(plaintext, masterKey, associatedData)
		require.NoError(t, err)

		// Truncate the encrypted data
		truncated := encrypted[:5]
		_, err = DecryptPrivateKey(truncated, masterKey, associatedData)
		assert.Error(t, err, "Decryption of truncated data should fail")
	})

	t.Run("Encrypt with invalid master key fails", func(t *testing.T) {
		plaintext := []byte("secret data")
		invalidKey := []byte("too-short")

		_, err := EncryptPrivateKey(plaintext, invalidKey, "test-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create cipher")
	})

	t.Run("Decrypt with invalid master key fails", func(t *testing.T) {
		invalidKey := []byte("too-short")
		data := []byte("some-data")

		_, err := DecryptPrivateKey(data, invalidKey, "test-id")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create cipher")
	})

	t.Run("Encrypt and decrypt large data", func(t *testing.T) {
		// Generate large plaintext (1MB)
		plaintext := make([]byte, 1024*1024)
		_, err := io.ReadFull(rand.Reader, plaintext)
		require.NoError(t, err)

		associatedData := "large-data-test"

		encrypted, err := EncryptPrivateKey(plaintext, masterKey, associatedData)
		require.NoError(t, err)

		decrypted, err := DecryptPrivateKey(encrypted, masterKey, associatedData)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(plaintext, decrypted), "Large data should encrypt and decrypt correctly")
	})

	t.Run("Encrypt and decrypt empty plaintext", func(t *testing.T) {
		plaintext := []byte{}
		associatedData := "empty-test"

		encrypted, err := EncryptPrivateKey(plaintext, masterKey, associatedData)
		require.NoError(t, err)

		decrypted, err := DecryptPrivateKey(encrypted, masterKey, associatedData)
		require.NoError(t, err)
		// Both empty slice and nil are acceptable for empty plaintext
		assert.Len(t, decrypted, 0, "Decrypted data should be empty")
	})

	t.Run("Tampered ciphertext fails decryption", func(t *testing.T) {
		plaintext := []byte("secret data")
		associatedData := "test-id"

		encrypted, err := EncryptPrivateKey(plaintext, masterKey, associatedData)
		require.NoError(t, err)

		// Tamper with the ciphertext
		if len(encrypted) > 20 {
			encrypted[20] ^= 0xFF
		}

		_, err = DecryptPrivateKey(encrypted, masterKey, associatedData)
		assert.Error(t, err, "Decryption of tampered data should fail")
	})
}

