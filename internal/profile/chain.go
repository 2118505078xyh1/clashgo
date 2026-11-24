package profile

import "clashgo/internal/config"

// BuildChain expands the proxy chain that starts at item. The chain is
// ordered "prev -> ... -> item -> ... -> next": we walk PrevProfile backwards
// (prepending each hop) and NextProfile forwards (appending each hop).
//
// Every visited UID is remembered, so a malformed configuration containing a
// cycle (A -> B -> A) terminates instead of looping forever, and a UID never
// appears twice in the result. A reference to a UID that is not in db ends
// that side of the walk.
func BuildChain(db *config.ProfilesDB, item *config.PrfItem) []string {
	if db == nil || item == nil {
		return nil
	}

	chain := []string{item.UID}
	visited := map[string]bool{item.UID: true}

	// Walk backwards along PrevProfile, prepending to keep chain order.
	// References to UIDs not present in db are ignored.
	for uid := prevProfile(item); uid != "" && !visited[uid]; {
		prev := db.Find(uid)
		if prev == nil {
			break
		}
		visited[uid] = true
		chain = append([]string{uid}, chain...)
		uid = prevProfile(prev)
	}

	// Walk forwards along NextProfile, appending to keep chain order.
	for uid := nextProfile(item); uid != "" && !visited[uid]; {
		next := db.Find(uid)
		if next == nil {
			break
		}
		visited[uid] = true
		chain = append(chain, uid)
		uid = nextProfile(next)
	}

	return chain
}

func prevProfile(item *config.PrfItem) string {
	if item == nil || item.Option == nil {
		return ""
	}
	return item.Option.PrevProfile
}

func nextProfile(item *config.PrfItem) string {
	if item == nil || item.Option == nil {
		return ""
	}
	return item.Option.NextProfile
}
