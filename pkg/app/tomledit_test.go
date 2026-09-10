package app

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpliceProfileBlock(t *testing.T) {
	const src = `# header comment
[profiles.keep]
url = "https://keep.example/mcp"

[profiles.gone]
url = "https://gone.example/mcp"

  [profiles.gone.headers]
  "X" = "y"

[profiles.tail]
url = "https://tail.example/mcp"
`
	out, ok := spliceProfileBlock(src, "gone", "")
	require.True(t, ok)
	assert.NotContains(t, out, "gone.example")
	assert.NotContains(t, out, "[profiles.gone.headers]", "nested tables go with the block")
	assert.Contains(t, out, "# header comment")
	assert.Contains(t, out, "[profiles.keep]")
	assert.Contains(t, out, "[profiles.tail]")

	// Replacement lands where the old block was, not at the end of the file.
	out, ok = spliceProfileBlock(src, "gone", "\n[profiles.gone]\nurl = \"https://new.example/mcp\"\n")
	require.True(t, ok)
	assert.Less(t, strings.Index(out, "new.example"), strings.Index(out, "[profiles.tail]"))

	// Last block in the file, and an unknown name.
	out, ok = spliceProfileBlock(src, "tail", "")
	require.True(t, ok)
	assert.NotContains(t, out, "tail.example")
	assert.True(t, strings.HasSuffix(out, "\n"))

	_, ok = spliceProfileBlock(src, "absent", "")
	assert.False(t, ok, "unknown profile must be reported, not silently 'removed'")
}

// A comment between two profiles documents the one below it: removing the
// profile above must not take it along.
func TestSpliceProfileBlockKeepsNeighbourComments(t *testing.T) {
	const src = `[profiles.gone]
url = "https://gone.example/mcp"

# the staging server, handle with care
[profiles.tail]
url = "https://tail.example/mcp"

# scratch notes at the end of the file
`
	out, ok := spliceProfileBlock(src, "gone", "")
	require.True(t, ok)
	assert.NotContains(t, out, "gone.example")
	assert.Contains(t, out, "# the staging server, handle with care",
		"the next profile's comment must survive")
	assert.Equal(t, `# the staging server, handle with care
[profiles.tail]
url = "https://tail.example/mcp"

# scratch notes at the end of the file
`, out)

	// Same rule at the end of the file: trailing notes are not part of the
	// last block.
	out, ok = spliceProfileBlock(src, "tail", "")
	require.True(t, ok)
	assert.Contains(t, out, "# scratch notes at the end of the file")
	assert.Contains(t, out, "# the staging server, handle with care",
		"an orphaned comment is the user's to delete, not ours")
}
