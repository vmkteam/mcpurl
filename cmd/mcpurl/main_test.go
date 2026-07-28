package main

import (
	"io"
	"testing"
	"time"

	"github.com/vmkteam/mcpurl/pkg/app"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantTarget string
		wantErr    bool
		check      func(*testing.T, *app.Options)
	}{
		{
			name: "flags before target", args: []string{"-v", "@acme"},
			wantTarget: "@acme",
			check:      func(t *testing.T, o *app.Options) { t.Helper(); assert.True(t, o.Verbose) },
		},
		{
			name: "flags after target", args: []string{"@acme", "-v", "--no-sse"},
			wantTarget: "@acme",
			check: func(t *testing.T, o *app.Options) {
				t.Helper()
				assert.True(t, o.Verbose)
				assert.True(t, o.NoSSE)
			},
		},
		{
			name: "flags around target", args: []string{"--timeout", "3s", "https://x.io/mcp", "-v"},
			wantTarget: "https://x.io/mcp",
			check: func(t *testing.T, o *app.Options) {
				t.Helper()
				assert.Equal(t, 3*time.Second, o.Timeout)
				assert.True(t, o.Verbose)
			},
		},
		{name: "no target", args: []string{"-v"}, wantTarget: ""},
		{name: "two positionals", args: []string{"@a", "@b"}, wantErr: true},
		{name: "unknown flag", args: []string{"--nope", "@a"}, wantErr: true},
		{
			name: "repeatable header", args: []string{"--header", "A:1", "--header", "B:2", "@a"},
			wantTarget: "@a",
			check: func(t *testing.T, o *app.Options) {
				t.Helper()
				assert.Equal(t, []string{"A:1", "B:2"}, o.Headers)
			},
		},
		{
			name: "scopes comma split", args: []string{"--scopes", "openid, profile ,roles", "@a"},
			wantTarget: "@a",
			check: func(t *testing.T, o *app.Options) {
				t.Helper()
				assert.Equal(t, []string{"openid", "profile", "roles"}, o.Scopes)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var o app.Options
			fs := newFlagSet("test", &o)
			fs.SetOutput(io.Discard)
			target, err := parseTarget(fs, tt.args)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantTarget, target)
			if tt.check != nil {
				tt.check(t, &o)
			}
		})
	}
}
