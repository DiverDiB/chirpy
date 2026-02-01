package main

import "testing"

func TestGetCleanedBody(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no profane words",
			input:    "This is a clean chirp",
			expected: "This is a clean chirp",
		},
		{
			name:     "single lowercase profane word",
			input:    "What a kerfuffle this is",
			expected: "What a **** this is",
		},
		{
			name:     "mixed case profane word",
			input:    "That is so Fornax",
			expected: "That is so ****",
		},
		{
			name:     "profane word with punctuation",
			input:    "Sharbert! is not allowed",
			expected: "Sharbert! is not allowed",
		},
		{
			name:     "profane, space, punc",
			input:    "Sharbert ! is not allowed either",
			expected: "**** ! is not allowed either",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := getCleanedBody(tt.input)
			if actual != tt.expected {
				t.Errorf("Expected: %s, got: %s", tt.expected, actual)
			}
		})
	}
}
