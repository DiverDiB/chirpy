package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
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

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedToken string
		expectedErr   bool
	}{
		{
			name: "valid bearer token",
			headers: http.Header{
				"Authorization": []string{"Bearer my-test-token-123"},
			},
			expectedToken: "my-test-token-123",
			expectedErr:   false,
		},
		{
			name:          "missing header",
			headers:       http.Header{},
			expectedToken: "",
			expectedErr:   true,
		},
		{
			name: "malformed header",
			headers: http.Header{
				"Authorization": []string{"ApiKey some-key"},
			},
			expectedToken: "",
			expectedErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GetBearerToken(tt.headers)
			if (err != nil) != tt.expectedErr {
				t.Errorf("GetBearerToken() error = %v, expectedErr %v", err, tt.expectedErr)
				return
			}
			if token != tt.expectedToken {
				t.Errorf("GetBearerToken() = %v, expected %v", token, tt.expectedToken)
			}
		})
	}
}
func TestJWTFlow(t *testing.T) {
	secret := "my-secret-key"
	userID := uuid.New()
	expiresIn := time.Hour

	// 1. Create a token
	token, err := MakeJWT(userID, secret, expiresIn)
	if err != nil {
		t.Fatalf("failed to make JWT: %v", err)
	}

	// 2. Validate the token
	validatedID, err := ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("failed to validate JWT: %v", err)
	}

	// 3. Check if the IDs match
	if validatedID != userID {
		t.Errorf("expected ID %v, got %v", userID, validatedID)
	}
}
func TestValidateJWTWrongSecret(t *testing.T) {
	correctSecret := "correct-secret"
	wrongSecret := "wrong-secret"
	userID := uuid.New()
	expiresIn := time.Hour

	// 1. Create a token signed with the WRONG secret
	token, err := MakeJWT(userID, wrongSecret, expiresIn)
	if err != nil {
		t.Fatalf("failed to make JWT: %v", err)
	}

	// 2. Try to validate it using the CORRECT secret
	_, err = ValidateJWT(token, correctSecret)

	// 3. It MUST return an error
	if err == nil {
		t.Error("expected error when validating token with wrong secret, but got nil")
	}
}
