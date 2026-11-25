#!/usr/bin/env bash
# 功能自检：逐项验证 ClashGo 的主要能力是否真的可用。
# 用法：bash scripts/verify-features.sh
set -u
B=http://127.0.0.1:9097
H="Authorization: Bearer clashgo"
PASS=0; FAIL=0

chk() { # chk <名称> <期望> <实际>
  if [ "$2" = "$3" ]; then printf "  [OK]   %-28s %s\n" "$1" "$3"; PASS=$((PASS+1));
  else printf "  [FAIL] %-28s 期望=%s 实际=%s\n" "$1" "$2" "$3"; FAIL=$((FAIL+1)); fi
}
chkc() { # chkc <名称> <子串> <文本>
  if echo "$3" | grep -q "$2"; then printf "  [OK]   %-28s %s\n" "$1" "$2"; PASS=$((PASS+1));
  else printf "  [FAIL] %-28s 缺少 %s (得到: %s)\n" "$1" "$2" "$(echo "$3"|head -c 60)"; FAIL=$((FAIL+1)); fi
}
code() { curl -sS -m 10 -o /dev/null -w "%{http_code}" "$@" 2>/dev/null; }
body() { curl -sS -m 10 "$@" 2>/dev/null; }

echo "== 内核连通性 =="
chk "内核 /version" "200" "$(code -H "$H" $B/version)"
chk "内核进程存在" "1" "$(tasklist 2>/dev/null | grep -c -i '^mihomo.exe')"

echo "== 代理组与节点 =="
P=$(body -H "$H" $B/proxies)
chkc "代理组列表" "Selector" "$P"
NOW=$(echo "$P" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const p=JSON.parse(s).proxies;const g=Object.values(p).find(v=>v.type==='Selector'&&v.all&&v.all.length>1);process.stdout.write(g?g.now:'')})" 2>/dev/null)
if [ -n "$NOW" ]; then printf "  [OK]   %-28s %s\n" "当前节点" "$NOW"; PASS=$((PASS+1)); else printf "  [FAIL] %-28s\n" "当前节点"; FAIL=$((FAIL+1)); fi
chk "节点延迟接口" "200" "$(code -m 20 -H "$H" "$B/proxies/$(node -e "console.log(encodeURIComponent(process.argv[1]))" "$NOW")/delay?timeout=8000&url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204")"

echo "== 模式切换 =="
for m in global direct rule; do
  chk "切到 $m" "204" "$(code -X PATCH -H "$H" -H 'Content-Type: application/json' $B/configs -d "{\"mode\":\"$m\"}")"
done

echo "== 规则与配置 =="
chk "规则接口" "200" "$(code -H "$H" $B/rules)"
RN=$(body -H "$H" $B/rules | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const r=JSON.parse(s).rules||[];process.stdout.write(String(r.length))})" 2>/dev/null)
if [ "${RN:-0}" -gt 10 ]; then printf "  [OK]   %-28s %s 条\n" "规则数量" "$RN"; PASS=$((PASS+1)); else printf "  [FAIL] %-28s %s\n" "规则数量" "$RN"; FAIL=$((FAIL+1)); fi
chk "配置接口" "200" "$(code -H "$H" $B/configs)"
chk "日志级别切换" "204" "$(code -X PATCH -H "$H" -H 'Content-Type: application/json' $B/configs -d '{"log-level":"debug"}')"
chk "关闭连接" "204" "$(code -X DELETE -H "$H" $B/connections/nonexistent)"

echo "== 代理出口 =="
# 先选一个延迟正常的节点，否则出口探测会因为节点不通而失败。
GRP=$(echo "$P" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const p=JSON.parse(s).proxies;const g=Object.entries(p).find(([k,v])=>v.type==='Selector'&&v.all&&v.all.length>1);process.stdout.write(g?g[0]:'')})" 2>/dev/null)
if [ -n "$GRP" ]; then
  GN=$(node -e "console.log(encodeURIComponent(process.argv[1]))" "$GRP")
  for cand in "香港 201 | 专线" "香港 202 | 专线" "香港 203 | 专线"; do
    CN=$(node -e "console.log(encodeURIComponent(process.argv[1]))" "$cand")
    if [ "$(code -m 20 -H "$H" "$B/proxies/$CN/delay?timeout=8000&url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204")" = "200" ]; then
      printf '{"name":"%s"}' "$cand" > /tmp/sel.json
      curl -sS -m 5 -X PUT -H "$H" -H 'Content-Type: application/json' \
        "$B/proxies/$GN" --data-binary @/tmp/sel.json -o /dev/null 2>/dev/null
      break
    fi
  done
  sleep 2
fi
IP=$(curl -sS -m 20 -x http://127.0.0.1:7897 https://api.ip.sb/ip 2>/dev/null | tr -d '\r\n')
if [ -n "$IP" ]; then printf "  [OK]   %-28s %s\n" "代理出口 IP" "$IP"; PASS=$((PASS+1)); else printf "  [FAIL] %-28s\n" "代理出口 IP"; FAIL=$((FAIL+1)); fi
chk "直连不被劫持" "200" "$(code https://api.ip.sb/ip)"

echo
echo "通过 $PASS / 失败 $FAIL"
[ "$FAIL" = "0" ]
