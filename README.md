# security-toolkit

`kotoba-lang/security-toolkit` — **nmap / wireshark / burpsuite に相当する security
tooling を pure `.cljc` で**。ADR-2609051100（superproject `90-docs/adr/`）。

3 tool は namespace 分離:
- `sec.scan` — port/host scanner（nmap 相当。TCP connect/SYN 判定は provider seam）
- `sec.pkt` — pcap 読み取り + protocol dissect（wireshark 相当。Ethernet/IPv4/TCP/UDP）
- `sec.http` — HTTP request 分析 + 再送/リピート構成（burpsuite 相当。MITM upstream は provider seam）

## 設計原則

- **pure `.cljc`。ambient authority を持たない。** 生 socket / raw capture /
  TLS upstream は `sec.io` protocol（`open-conn` / `send` / `recv` / `close`）を
  通して注入する。JVM/nbb 用の参照 provider は `sec.io.jvm` / `sec.io.node`。
- scan 対象への実接続は op 側 policy gate（`:approval-required` 既定、
  `capability-ble-scan` と同型）を通す。無許可 network への攻撃的 scan は非目標。
- GUI は無い。dissect と構成は data（EDN map）で出す。

## 使い方

```clojure
(require '[sec.scan :as scan])

;; spec は map（:hosts / :ports）。provider は inject 必須（deny-by-default）。
;; ここでは test suite 同梱の test 側 fake (sec.io.fake/fake-provider、main には無い) を使う。実運用では sec.io/IOProvider を実装して渡す。
(scan/connect-scan {:hosts ["127.0.0.1"] :ports [80 443 8080]}
                   {:provider my-provider})
;=> [{:host "127.0.0.1", :port 80,   :state :open}
;    {:host "127.0.0.1", :port 443,  :state :closed}
;    {:host "127.0.0.1", :port 8080, :state :filtered}]

(require '[sec.pkt :as pkt])

;; pcap ファイルのバイト列（int 0..255 の array）。読み込み自体は seam の外。
;; slurp 等の file I/O は pure `.cljc` に存在しない。
(pkt/dissect-pcap bytes)
;=> [{:frame 1, :ts-sec 1700000000, :ts-usec 123456, :ts-unit :us,
;     :caplen 50, :origlen 50, :eth {...}, :ip {...}, :l4 {...}}]

(require '[sec.http :as http])

(http/parse-request "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
;=> {:method "GET", :path "/", :version "HTTP/1.1",
;    :headers {"host" "x"}, :body ""}
;; （header 名は lower-case になる。同名 header は vector 値に重复集約）
```

## test

```bash
nbb --classpath src:test test/run.cljk
```
