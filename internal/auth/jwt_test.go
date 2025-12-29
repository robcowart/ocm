package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateToken(t *testing.T) {
	secret := "test-secret-key"
	issuer := "test-issuer"
	expiration := 24 * time.Hour

	t.Run("Generate valid token", func(t *testing.T) {
		token, err := GenerateToken("user123", "testuser", "admin", secret, issuer, expiration)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("Generate token with different user details", func(t *testing.T) {
		token1, err := GenerateToken("user1", "alice", "user", secret, issuer, expiration)
		require.NoError(t, err)

		token2, err := GenerateToken("user2", "bob", "admin", secret, issuer, expiration)
		require.NoError(t, err)

		assert.NotEqual(t, token1, token2, "Tokens for different users should be different")
	})

	t.Run("Generate token with short expiration", func(t *testing.T) {
		token, err := GenerateToken("user123", "testuser", "admin", secret, issuer, 1*time.Second)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("Generate token with long expiration", func(t *testing.T) {
		token, err := GenerateToken("user123", "testuser", "admin", secret, issuer, 365*24*time.Hour)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("Generate token with empty secret", func(t *testing.T) {
		token, err := GenerateToken("user123", "testuser", "admin", "", issuer, expiration)
		// Empty secret should still generate a token (though not secure)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})
}

func TestValidateToken(t *testing.T) {
	secret := "test-secret-key"
	issuer := "test-issuer"
	expiration := 24 * time.Hour

	t.Run("Validate valid token", func(t *testing.T) {
		token, err := GenerateToken("user123", "testuser", "admin", secret, issuer, expiration)
		require.NoError(t, err)

		claims, err := ValidateToken(token, secret)
		require.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "user123", claims.UserID)
		assert.Equal(t, "testuser", claims.Username)
		assert.Equal(t, "admin", claims.Role)
		assert.Equal(t, issuer, claims.Issuer)
	})

	t.Run("Validate token with wrong secret", func(t *testing.T) {
		token, err := GenerateToken("user123", "testuser", "admin", secret, issuer, expiration)
		require.NoError(t, err)

		_, err = ValidateToken(token, "wrong-secret")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse token")
	})

	t.Run("Validate expired token", func(t *testing.T) {
		token, err := GenerateToken("user123", "testuser", "admin", secret, issuer, -1*time.Hour)
		require.NoError(t, err)

		_, err = ValidateToken(token, secret)
		assert.Error(t, err)
	})

	t.Run("Validate invalid token string", func(t *testing.T) {
		_, err := ValidateToken("invalid-token-string", secret)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse token")
	})

	t.Run("Validate malformed token", func(t *testing.T) {
		_, err := ValidateToken("header.payload.signature", secret)
		assert.Error(t, err)
	})

	t.Run("Validate empty token", func(t *testing.T) {
		_, err := ValidateToken("", secret)
		assert.Error(t, err)
	})

	t.Run("Validate token preserves all claims", func(t *testing.T) {
		userID := "special-user-id-12345"
		username := "special_username"
		role := "superadmin"

		token, err := GenerateToken(userID, username, role, secret, issuer, expiration)
		require.NoError(t, err)

		claims, err := ValidateToken(token, secret)
		require.NoError(t, err)
		assert.Equal(t, userID, claims.UserID)
		assert.Equal(t, username, claims.Username)
		assert.Equal(t, role, claims.Role)
	})

	t.Run("Validate token near expiration", func(t *testing.T) {
		// Generate token with 1 second expiration
		token, err := GenerateToken("user123", "testuser", "admin", secret, issuer, 1*time.Second)
		require.NoError(t, err)

		// Token should be valid immediately
		claims, err := ValidateToken(token, secret)
		require.NoError(t, err)
		assert.NotNil(t, claims)

		// Wait for token to expire
		time.Sleep(1500 * time.Millisecond)

		// Token should now be expired
		_, err = ValidateToken(token, secret)
		assert.Error(t, err)
	})

	t.Run("Validate token issued time", func(t *testing.T) {
		before := time.Now().Add(-1 * time.Second) // Allow 1 second buffer
		token, err := GenerateToken("user123", "testuser", "admin", secret, issuer, expiration)
		require.NoError(t, err)
		after := time.Now().Add(1 * time.Second) // Allow 1 second buffer

		claims, err := ValidateToken(token, secret)
		require.NoError(t, err)

		// IssuedAt should be between before and after (with buffer)
		assert.True(t, claims.IssuedAt.Time.After(before) || claims.IssuedAt.Time.Equal(before))
		assert.True(t, claims.IssuedAt.Time.Before(after) || claims.IssuedAt.Time.Equal(after))
	})

	t.Run("Validate token expiry time", func(t *testing.T) {
		expirationDuration := 1 * time.Hour
		token, err := GenerateToken("user123", "testuser", "admin", secret, issuer, expirationDuration)
		require.NoError(t, err)

		claims, err := ValidateToken(token, secret)
		require.NoError(t, err)

		// ExpiresAt should be roughly 1 hour from now (allowing small time drift)
		expectedExpiry := time.Now().Add(expirationDuration)
		timeDiff := claims.ExpiresAt.Time.Sub(expectedExpiry).Abs()
		assert.Less(t, timeDiff, 1*time.Second)
	})
}

func TestGenerateAndValidateToken_RoundTrip(t *testing.T) {
	t.Run("Generate and validate multiple tokens", func(t *testing.T) {
		secret := "test-secret"
		issuer := "test-issuer"

		testCases := []struct {
			userID   string
			username string
			role     string
		}{
			{"user1", "alice", "admin"},
			{"user2", "bob", "user"},
			{"user3", "charlie", "moderator"},
		}

		for _, tc := range testCases {
			token, err := GenerateToken(tc.userID, tc.username, tc.role, secret, issuer, 24*time.Hour)
			require.NoError(t, err)

			claims, err := ValidateToken(token, secret)
			require.NoError(t, err)
			assert.Equal(t, tc.userID, claims.UserID)
			assert.Equal(t, tc.username, claims.Username)
			assert.Equal(t, tc.role, claims.Role)
		}
	})

	t.Run("Different secrets produce incompatible tokens", func(t *testing.T) {
		secret1 := "secret1"
		secret2 := "secret2"
		issuer := "test-issuer"

		token, err := GenerateToken("user123", "testuser", "admin", secret1, issuer, 24*time.Hour)
		require.NoError(t, err)

		// Validating with different secret should fail
		_, err = ValidateToken(token, secret2)
		assert.Error(t, err)

		// Validating with correct secret should succeed
		claims, err := ValidateToken(token, secret1)
		require.NoError(t, err)
		assert.NotNil(t, claims)
	})
}

