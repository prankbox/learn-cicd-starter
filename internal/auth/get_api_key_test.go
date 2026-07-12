package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("returns error when no authorization header is included", func(t *testing.T) {
		headers := http.Header{}
		apiKey, err := GetAPIKey(headers)
		if apiKey != "" {
			t.Errorf("expected empty API key, got %q", apiKey)
		}
		if !errors.Is(err, ErrNoAuthHeaderIncluded) {
			t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("returns error when authorization header is malformed", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer my-api-key")
		apiKey, err := GetAPIKey(headers)
		if apiKey != "" {
			t.Errorf("expected empty API key, got %q", apiKey)
		}
		if err == nil || err.Error() != "malformed authorization header" {
			t.Errorf("expected malformed authorization header error, got %v", err)
		}
	})

	t.Run("returns API key when authorization header is valid", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey my-api-key")
		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if apiKey != "my-api-key" {
			t.Errorf("expected API key %q, got %q", "my-api-key", apiKey)
		}
	})
}
