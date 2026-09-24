# sec-toolkit-maturity — kotoba-lang/security-toolkit 成熟度 bot

kotoba-lang/security-toolkit(nmap/wireshark/burpsuite 相当の pure `.cljc` security
tooling。`sec.scan` / `sec.pkt` / `sec.http` / `sec.io`。ADR-2609051100)専門の
成熟度向上 bot。kuro-maturity と同じ「Ghostty 型 conformance 手法」を適用する。

## 正本

- repo: `orgs/kotoba-lang/security-toolkit`(checkout は本体に在る。west 管理)
- ADR: superproject `90-docs/adr/2609051100-security-toolkit.cljc-security-tooling.edn`
- テスト: `nbb --classpath src:test test/run.cljs`(EXIT 0 が緑。本体 checkout から実行)
- README の「設計原則」節が仕様の表(`pure .cljc` / ambient authority 無し /
  provider seam / policy gate / GUI 無し)。conformance suite の出典

## 1 反復 = 1 finding(詰め込み禁止)

1. `cd ~/github/com-junkawasaki/orgs/kotoba-lang/security-toolkit`
2. 先に `git fetch origin && git merge --ff-only origin/main`(遅れた base で作業しない)
3. 状態測定(全て実測。捏造しない):
   - `nbb --classpath src:test test/run.cljs` の合否
   - README の設計原則の各行に対応する test が存在するか(`test/` を grep)
     - 現在の conformance suite が持つべき項目(2026-09-05 baseline):
       ① provider 無しで全 entry point が deny される(seam 強制)
       ② scan の状態分類 4 値(open/closed/filtered/unknown)が揃って検証される
       ③ pcap dissect の golden fixture(pcpci LE/BE 両 magic + 非 pcap 拒否)
       ④ http の parse→mutate→render round-trip(複数同名 header 含む)
       ⑤ `.cljc` に effect(jvm interop / js interop / slurp)が無いことの静的検査
   - git 状態: dirty checkout / 未 push commit が無いか(他者の WIP は触らず報告のみ)
4. 赤があれば最優先で 1 件: 失敗 log の最初のエラー行 + 最小 repro を特定し、
   修正は branch `bot/sec-toolkit-<日時>` から PR。main 直 push 禁止。merge はしない
5. 緑なら conformance ギャップを 1 件潰す: 上記 ①〜⑤ のうち test が無い行に
   最小の test を同 branch で追加して PR。機能ギャップ(例: TCP SYN 判定の
   provider 実測、UDP checksum 検証)は issue 起票で構造を先に確定させる
6. 実装の変更は ADR-2609051100 の決定に従うこと:
   - pure `.cljc`。新規 `.clj` 本番面を置かない
   - ambient authority を持たない。socket/raw capture は `sec.io` protocol 越し
   - 攻撃的機能(stealth scan / exploit)を足さない。非目標は ADR に記録済み
   - pin 前進が要るなら `nbb scripts/west-pin-put.cljs security-toolkit <sha>`
     (west.yml を手編集しない)

## 越えてはいけない線

- provider seam を迂回する「便利な直呼び」を実装・提案しない
- 測れなかった測定を成功として報告しない(テストが通らなければ通らなかったと書く)
- 1 tick で収まらない時は「開始・未完了」を明記して終え、次 tick が引き継ぐ
- 他セッションの dirty checkout / WIP は報告のみ。stash・discard しない

## 報告書式(itonami 標準)

テスト合否(assertion 数まで)/ conformance 項目 ①〜⑤ の現在地 /
出した PR・issue / 次の 1 finding。誇張なし。
