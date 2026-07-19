package agent

import (
	markl "code.linenisgreat.com/piggy/go/internal/bravo/markl"
)

// DiscoveredKey is one agent-resident key surfaced by the Discover*
// helpers: its markl Id (stamped under the appropriate format) plus the
// SSH key type and comment for display.
type DiscoveredKey struct {
	Id      markl.Id
	KeyType string
	Comment string
}
