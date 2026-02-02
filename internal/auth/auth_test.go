package auth

import (
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	secret := "well-kept-secret"
	userID := uuid.New()

	t.Run("Valid Token", func(t *testing.T) {
		// 1. Create a token that lasts for 1 minute
		token, err := MakeJWT(userID, secret, time.Minute)
		if err != nil {
			t.Fatalf("Failed to make JWT: %v", err)
		}

		// 2. Validate it immediately
		parsedID, err := ValidateJWT(token, secret)
		if err != nil {
			t.Errorf("Validation failed for valid token: %v", err)
		}

		// 3. Ensure the ID matches
		if parsedID != userID {
			t.Errorf("Expected ID %v, got %v", userID, parsedID)
		}
	})

	t.Run("Expired Token", func(t *testing.T) {
		// Create a token that expired 1 hour ago
		token, err := MakeJWT(userID, secret, -time.Hour)
		if err != nil {
			t.Fatalf("Failed to make JWT: %v", err)
		}

		// Validation should return an error
		_, err = ValidateJWT(token, secret)
		if err == nil {
			t.Error("Validation should have failed for expired token")
		}
	})

	t.Run("Wrong Secret", func(t *testing.T) {
		token, _ := MakeJWT(userID, secret, time.Minute)

		// Try to validate with the wrong secret string
		_, err := ValidateJWT(token, "wrong-password")
		if err == nil {
			t.Error("Validation should have failed for incorrect secret")
		}
	})
}
