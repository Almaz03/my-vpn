package telegram

type Allowlist map[int64]struct{}

func NewAllowlist(ids []int64) Allowlist {
	result := make(Allowlist, len(ids))
	for _, id := range ids {
		if id > 0 {
			result[id] = struct{}{}
		}
	}
	return result
}

func (a Allowlist) Authorized(id int64) bool {
	_, ok := a[id]
	return ok
}
