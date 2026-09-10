// Text-level editing of config.toml: replace or drop one [profiles.<name>]
// block, leaving every other byte of the file alone. Deliberately not a TOML
// round-trip — the file is hand-written, full of comments and deliberate
// alignment, and a marshal/unmarshal pass would silently normalize all of it
// away (02-cli.md).

package app

import "strings"

// spliceProfileBlock replaces the [profiles.<name>] section — including its
// nested tables and the blank line separating it from the block above — with
// block, or drops the section when block is empty. ok is false when no such
// section exists (an inline `profiles.<name> = {…}`, say), which the caller
// must report rather than silently treat as a removal.
func spliceProfileBlock(src, name, block string) (out string, ok bool) {
	lines := strings.SplitAfter(src, "\n")
	start, end := -1, len(lines)
	for i, line := range lines {
		key, isTable := tableKey(line)
		if !isTable {
			continue
		}
		if profileSection(key, name) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			end = i // the next unrelated table ends the block
			break
		}
	}
	if start < 0 {
		return src, false
	}
	for start > 0 && blankLine(lines[start-1]) {
		start-- // the blank separator belongs to the block being replaced
	}
	// A comment sitting between two profiles documents the one below it, not
	// the one being removed — give it (and its separating blank line) back.
	for end > start && (blankLine(lines[end-1]) || commentLine(lines[end-1])) {
		end--
	}
	for start == 0 && block == "" && end < len(lines) && blankLine(lines[end]) {
		end++ // nothing above to separate from: don't leave the file opening blank
	}
	out = strings.Join(lines[:start], "") + block + strings.Join(lines[end:], "")
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out, true
}

func blankLine(line string) bool { return strings.TrimSpace(line) == "" }

func commentLine(line string) bool { return strings.HasPrefix(strings.TrimSpace(line), "#") }

// tableKey parses a TOML table header line: `  [profiles.acme] # note` →
// "profiles.acme". Array-of-tables headers ("[[x]]") count as headers too —
// they end the preceding section — but never match a profile.
func tableKey(line string) (string, bool) {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, "[") {
		return "", false
	}
	inner, _, ok := strings.Cut(s[1:], "]")
	if !ok {
		return "", false
	}
	return strings.TrimSpace(inner), true
}

// profileSection reports whether a table key addresses [profiles.<name>] or a
// table nested under it (e.g. [profiles.<name>.headers]).
func profileSection(key, name string) bool {
	parts := splitTOMLKey(key)
	return len(parts) >= 2 && parts[0] == "profiles" && parts[1] == name
}

// splitTOMLKey splits a dotted key, honouring quoted parts: `profiles."a.b"`
// → ["profiles", "a.b"].
func splitTOMLKey(key string) []string {
	var (
		parts []string
		cur   strings.Builder
		quote rune
	)
	for _, r := range key {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			quote = r
		case r == '.':
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	return append(parts, strings.TrimSpace(cur.String()))
}
