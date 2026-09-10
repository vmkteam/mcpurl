package redact

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokens(t *testing.T) {
	const jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	tests := []struct {
		name, in, want string
	}{
		{"gateway echoes the credential",
			`{"error_description":"Jwt expired: ` + jwt + `"}`,
			`{"error_description":"Jwt expired: [redacted JWT]"}`},
		{"unsigned two-segment token",
			"token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0",
			"token=[redacted JWT]"},
		{"signature must not survive the header",
			jwt, "[redacted JWT]"},
		{"plain diagnosis is untouched",
			`auth: invalid token: oidc: malformed jwt: unexpected signature algorithm "HS256"`,
			`auth: invalid token: oidc: malformed jwt: unexpected signature algorithm "HS256"`},
		{"a word starting with eyJ is not a token", "eyJ.x", "eyJ.x"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Tokens(tt.in)
			assert.Equal(t, tt.want, got)
			assert.NotContains(t, got, jwt)
		})
	}
}
