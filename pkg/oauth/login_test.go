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

// The loopback callback is what a dynamic client registers, so the port
// default has to hold on both sides.
func TestRedirectURI(t *testing.T) {
	assert.Equal(t, "http://127.0.0.1:18075/callback", (&Flow{}).redirectURI())
	assert.Equal(t, "http://127.0.0.1:19000/callback", (&Flow{CallbackPort: 19000}).redirectURI())
}

// A login timeout names the way out only for a dynamic client: a static one
// has nothing logout could re-register.
func TestUnknownClientHint(t *testing.T) {
	assert.Empty(t, (&Flow{ClientID: "static"}).unknownClientHint())

	hint := (&Flow{reg: &Registration{ClientID: "dyn-7"}}).unknownClientHint()
	assert.Contains(t, hint, "`mcpurl logout`")
	assert.Contains(t, hint, "dyn-7")
}
