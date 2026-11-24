package minikernel

import "clashgo/internal/ruleindex"

// configSnapshot 是一份不可变的运行配置快照，供热重载时原子替换。
// 现有连接继续用旧快照跑完，新连接用新快照——不中断长连接。
type configSnapshot struct {
	Mode    string
	Rules   []Rule
	Proxies map[string]ProxyAdapter

	// 规则加速：当所有规则都是纯域名规则且数量较多时，用 Trie 加速。
	// pureDomain 为 true 时，domainTrie 覆盖全部规则（priority = 规则索引）。
	domainTrie *ruleindex.DomainTrie
	pureDomain bool
}

// publishSnapshot 从当前可写字段发布一份新快照（配置变更后调用）。
func (k *Kernel) publishSnapshot() {
	proxies := make(map[string]ProxyAdapter, len(k.Proxies))
	for n, p := range k.Proxies {
		proxies[n] = p
	}
	rules := append([]Rule(nil), k.Rules...)
	snap := &configSnapshot{Mode: k.Mode, Rules: rules, Proxies: proxies}

	// 构建域名 Trie：仅当规则数达到阈值且全部为纯域名规则时启用，
	// 保证 first-match-wins 语义不被破坏。
	if len(rules) >= 200 {
		pure := true
		trie := ruleindex.NewDomainTrie()
		for i, r := range rules {
			switch rr := r.(type) {
			case *domainRule:
				trie.InsertExact(rr.lower, i, rr.adapter)
			case *domainSuffixRule:
				trie.Insert(rr.lower, i, rr.adapter)
			case *domainKeywordRule:
				trie.InsertKeyword(rr.lower, i, rr.adapter)
			default:
				pure = false
				break
			}
		}
		if pure {
			snap.domainTrie = trie
			snap.pureDomain = true
		}
	}
	k.cfgSnap.Store(snap)
}

func (k *Kernel) initSnapshot() { k.publishSnapshot() }

// snapshot 返回当前配置快照（可能为 nil 时回退到可写字段）。
func (k *Kernel) snapshot() *configSnapshot {
	if s := k.cfgSnap.Load(); s != nil {
		return s
	}
	return &configSnapshot{Mode: k.Mode, Rules: k.Rules, Proxies: k.Proxies}
}
