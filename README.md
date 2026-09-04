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
(scan/connect-scan "127.0.0.1" [80 443 8080] {:provider my-provider})
;=> [{:port 80  :state :open} {:port 443 :state :closed} ...]

(require '[sec.pkt :as pkt])
(pkt/dissect-pcap (slurp "capture.pcap"))
;=> [{:frame 1 :eth {...} :ip {...} :tcp {...}} ...]

(require '[sec.http :as http])
(http/parse-request "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
;=> {:method "GET" :path "/" :headers {"Host" "x"} :body ""}
```

## test

```bash
nbb --classpath src:test test/run.cljs
```
