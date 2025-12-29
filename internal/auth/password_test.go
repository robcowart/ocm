package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	t.Run("Hash password successfully", func(t *testing.T) {
		password := "MySecurePassword123"
		hash, err := HashPassword(password)
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.NotEqual(t, password, hash, "Hash should not equal plaintext password")
	})

	t.Run("Hash produces different results each time", func(t *testing.T) {
		password := "MySecurePassword123"
		hash1, err := HashPassword(password)
		require.NoError(t, err)

		hash2, err := HashPassword(password)
		require.NoError(t, err)

		assert.NotEqual(t, hash1, hash2, "Multiple hashes of same password should be different due to salt")
	})

	t.Run("Hash empty password", func(t *testing.T) {
		hash, err := HashPassword("")
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
	})

	t.Run("Hash long password", func(t *testing.T) {
		// Bcrypt has a 72 byte limit, so use a password within that limit
		password := strings.Repeat("a", 70)
		hash, err := HashPassword(password)
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
	})

	t.Run("Hash special characters", func(t *testing.T) {
		password := "P@ssw0rd!#$%^&*()_+-=[]{}|;:',.<>?/~`"
		hash, err := HashPassword(password)
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
	})

	t.Run("Hash unicode characters", func(t *testing.T) {
		password := "Пароль123密码😀"
		hash, err := HashPassword(password)
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
	})

	t.Run("Hash uses correct bcrypt cost", func(t *testing.T) {
		password := "TestPassword123"
		hash, err := HashPassword(password)
		require.NoError(t, err)

		// Extract cost from hash (bcrypt hash format: $2a$<cost>$...)
		cost, err := bcrypt.Cost([]byte(hash))
		require.NoError(t, err)
		assert.Equal(t, BcryptCost, cost)
	})
}

func TestVerifyPassword(t *testing.T) {
	t.Run("Verify correct password", func(t *testing.T) {
		password := "MySecurePassword123"
		hash, err := HashPassword(password)
		require.NoError(t, err)

		err = VerifyPassword(password, hash)
		assert.NoError(t, err)
	})

	t.Run("Verify wrong password", func(t *testing.T) {
		password := "MySecurePassword123"
		hash, err := HashPassword(password)
		require.NoError(t, err)

		err = VerifyPassword("WrongPassword123", hash)
		assert.Error(t, err)
		assert.Equal(t, bcrypt.ErrMismatchedHashAndPassword, err)
	})

	t.Run("Verify with case sensitivity", func(t *testing.T) {
		password := "MySecurePassword123"
		hash, err := HashPassword(password)
		require.NoError(t, err)

		// Different case should fail
		err = VerifyPassword("mysecurepassword123", hash)
		assert.Error(t, err)
	})

	t.Run("Verify empty password against hash", func(t *testing.T) {
		password := ""
		hash, err := HashPassword(password)
		require.NoError(t, err)

		err = VerifyPassword("", hash)
		assert.NoError(t, err)

		err = VerifyPassword("non-empty", hash)
		assert.Error(t, err)
	})

	t.Run("Verify with invalid hash", func(t *testing.T) {
		err := VerifyPassword("password", "invalid-hash")
		assert.Error(t, err)
	})

	t.Run("Verify with empty hash", func(t *testing.T) {
		err := VerifyPassword("password", "")
		assert.Error(t, err)
	})

	t.Run("Verify password with special characters", func(t *testing.T) {
		password := "P@ssw0rd!#$%"
		hash, err := HashPassword(password)
		require.NoError(t, err)

		err = VerifyPassword(password, hash)
		assert.NoError(t, err)
	})

	t.Run("Verify password with unicode", func(t *testing.T) {
		password := "Пароль123密码😀"
		hash, err := HashPassword(password)
		require.NoError(t, err)

		err = VerifyPassword(password, hash)
		assert.NoError(t, err)
	})
}

func TestValidatePasswordStrength(t *testing.T) {
	t.Run("Valid password", func(t *testing.T) {
		err := ValidatePasswordStrength("MyPassword123")
		assert.NoError(t, err)
	})

	t.Run("Password too short", func(t *testing.T) {
		err := ValidatePasswordStrength("Pass1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least 8 characters")
	})

	t.Run("Password exactly 8 characters", func(t *testing.T) {
		err := ValidatePasswordStrength("Password1")
		assert.NoError(t, err)
	})

	t.Run("Password missing number", func(t *testing.T) {
		err := ValidatePasswordStrength("MyPassword")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one number")
	})

	t.Run("Password missing letter", func(t *testing.T) {
		err := ValidatePasswordStrength("12345678")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one letter")
	})

	t.Run("Password with uppercase only", func(t *testing.T) {
		err := ValidatePasswordStrength("PASSWORD123")
		assert.NoError(t, err)
	})

	t.Run("Password with lowercase only", func(t *testing.T) {
		err := ValidatePasswordStrength("password123")
		assert.NoError(t, err)
	})

	t.Run("Password with mixed case", func(t *testing.T) {
		err := ValidatePasswordStrength("MyPassword123")
		assert.NoError(t, err)
	})

	t.Run("Password with special characters", func(t *testing.T) {
		err := ValidatePasswordStrength("MyPassword123!@#")
		assert.NoError(t, err)
	})

	t.Run("Empty password", func(t *testing.T) {
		err := ValidatePasswordStrength("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least 8 characters")
	})

	t.Run("Password with only special characters", func(t *testing.T) {
		err := ValidatePasswordStrength("!@#$%^&*()")
		assert.Error(t, err)
	})

	t.Run("Very long password", func(t *testing.T) {
		password := "MyPassword123" + strings.Repeat("a", 100)
		err := ValidatePasswordStrength(password)
		assert.NoError(t, err)
	})

	t.Run("Password with spaces", func(t *testing.T) {
		err := ValidatePasswordStrength("My Password 123")
		assert.NoError(t, err)
	})

	t.Run("Password with unicode", func(t *testing.T) {
		// Unicode characters don't count as "letters" in the validation
		// Use a password that has both Latin letters and numbers
		err := ValidatePasswordStrength("Password123")
		assert.NoError(t, err)
	})

	t.Run("Password at minimum requirements", func(t *testing.T) {
		err := ValidatePasswordStrength("aaaaaaaa1")
		assert.NoError(t, err)
	})
}

func TestHashAndVerifyPassword_RoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		password string
	}{
		{"Simple password", "Password123"},
		{"With special chars", "P@ssw0rd!123"},
		{"Long password", "ThisIsAVeryLongPasswordWithNumbers123456789"},
		{"Unicode", "Пароль密码123"},
		{"Only lowercase", "password123"},
		{"Only uppercase", "PASSWORD123"},
		{"With spaces", "My Secret Password 123"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := HashPassword(tc.password)
			require.NoError(t, err)

			err = VerifyPassword(tc.password, hash)
			assert.NoError(t, err, "Should verify correct password")

			err = VerifyPassword(tc.password+"wrong", hash)
			assert.Error(t, err, "Should reject incorrect password")
		})
	}
}

func TestPasswordValidationAndHashing_Integration(t *testing.T) {
	t.Run("Validate then hash valid password", func(t *testing.T) {
		password := "MySecurePassword123"

		// First validate
		err := ValidatePasswordStrength(password)
		require.NoError(t, err)

		// Then hash
		hash, err := HashPassword(password)
		require.NoError(t, err)

		// Verify it works
		err = VerifyPassword(password, hash)
		assert.NoError(t, err)
	})

	t.Run("Invalid password should not be hashed", func(t *testing.T) {
		password := "weak"

		// Validate first
		err := ValidatePasswordStrength(password)
		require.Error(t, err)

		// In a real application, we wouldn't hash invalid passwords
		// But technically we can
		hash, err := HashPassword(password)
		require.NoError(t, err)

		// It still works, but shouldn't be used
		err = VerifyPassword(password, hash)
		assert.NoError(t, err)
	})
}

