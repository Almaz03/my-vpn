package telegram

type Allowlist map[int64]struct{}

func NewAllowlist(ids []int64) Allowlist {
	result := make(Allowlist, len(ids))
	for _, id := range ids {
		result[id] = struct{}{}
	}
	return result
}

func (a Allowlist) Authorized(id int64) bool {
	_, ok := a[id]
	return ok
}

// The transport is intentionally not started by the MVP. Telegram updates must
// be authenticated with Authorized before any command is dispatched, and full
// VPN configurations or private keys must never be sent through Telegram.
