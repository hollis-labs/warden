// Package scopes validates Warden's audience and scope vocabulary. An audience is one app id; a scope is
// <audience>.<verb>, where the verb may have dotted parts (hadron.profile.standard). Wildcards are never
// issued.
package scopes

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// MaxPerToken bounds the scopes one request or token carries.
const MaxPerToken = 16

var (
	audRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	verbRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}(\.[a-z0-9][a-z0-9_-]{0,31}){0,3}$`)
)

// ValidAudience reports whether aud is one app id.
func ValidAudience(aud string) bool { return audRe.MatchString(aud) }

// Normalize checks every scope belongs to aud and returns the sorted, de-duplicated set.
func Normalize(aud string, in []string) ([]string, error) {
	if !ValidAudience(aud) {
		return nil, errors.New("audience must be one app id (lowercase letters, digits, dashes)")
	}
	if len(in) == 0 || len(in) > MaxPerToken {
		return nil, fmt.Errorf("request between 1 and %d scopes", MaxPerToken)
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		verb, ok := strings.CutPrefix(s, aud+".")
		if !ok || !verbRe.MatchString(verb) {
			return nil, fmt.Errorf("scope %q must be %s.<verb> with no wildcard", s, aud)
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// Subset reports whether every scope in want is in have.
func Subset(want, have []string) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

// Split parses a space- or comma-separated scope string.
func Split(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' })
}
