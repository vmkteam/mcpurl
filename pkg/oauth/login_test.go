package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Granted vs. requested — the distinction that made a stored token claim a
// refresh capability it did not have (see grantedScopes).
func TestGrantedScopes(t *testing.T) {
	requested := []string{"openid", "profile", "email", "offline_access"}

	assert.Equal(t, []string{"openid", "email", "profile"},
		grantedScopes("openid email profile", requested),
		"the AS response must win over the request")

	// RFC 6749 §5.1: the field may be omitted when it matches the request.
	assert.Equal(t, requested, grantedScopes("", requested))
}
