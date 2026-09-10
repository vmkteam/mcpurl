package app

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// claude-config used to be the one command that insisted on the "@" — the
// same asymmetry that made `uninstall @name` fail from the other side.
func TestClaudeConfigAcceptsBareName(t *testing.T) {
	writeConfig(t)
	a, err := New(Options{}, nil)
	require.NoError(t, err)

	var bare, at strings.Builder
	require.NoError(t, a.ClaudeConfig(&bare, "acme", ""))
	require.NoError(t, a.ClaudeConfig(&at, "@acme", ""))
	assert.Equal(t, at.String(), bare.String(), "both spellings render the same snippet")
	assert.Contains(t, bare.String(), "https://mcp.acme.example/mcp")
	assert.Contains(t, bare.String(), `"@acme"`,
		"the snippet is config: spell the reference the way install writes it")
}
