(ns sec.pure-cljc-test
  "Conformance ⑤: static check that production sources stay pure `.cljc`.
  No ambient authority / host-only effects in src/: slurp, JVM interop,
  clojure.java.io, clj-only requires, or cljs js/ host interop. (ADR-2609051100).

  A text guard with no positive control passes vacuously whenever src happens
  not to contain the form yet — that is how js/parseInt slipped through until
  PR #20. forbidden-guard-detects-violators-test now pins every pattern
  against its own violator example (and also catches js* reader interop,
  goog.* Closure refs, and (.method)/(.-field) member access), while
  forbidden-guard-clean-forms-test pins idiomatic pure forms so the guard
  can never be 'fixed' into a sledgehammer.

  PR #20 closed the cljs side of host interop (js/parseInt); the JVM twin —
  (Integer/parseInt ...) static-call syntax and the (.. obj (method)) macro —
  was still a blind spot: (.. fails the \\(\\.[-a-zA-Z] class (second char is
  a dot) and Class/method has no js/ marker. Both are pinned now, with
  docstring-text negative controls so prose like \"Port/host scanner\" in
  src docstrings is not misread as interop."
  (:require [clojure.test :refer [deftest is]]
            [clojure.string :as str]
            [clojure.set :as set]))

;; nbb test runner: reading src files here is test-side only; production
;; sources themselves must contain none of these effect forms.
(def fs (js/require "fs"))

(def src-dir "src/sec")

;; derived from the filesystem so a new production file is purity-checked
;; automatically instead of silently escaping conformance ⑤ until listed here
(def src-files
  (->> (.readdirSync fs src-dir)
       (filter #(str/ends-with? % ".cljc"))
       (map #(str src-dir "/" %))
       sort))

(defn- read-src [path]
  (.readFileSync fs path "utf8"))

(def forbidden
  [#"slurp"                    ; file I/O
   #"clojure\.java\.io"        ; clj-only I/O namespace
   #"\bSystem[/.]"             ; JVM interop (System/getProperty and System/foo)
   #"java\.(io|net|lang)\."    ; JVM namespace interop
   #"\.getMethod\b|\.invoke\b" ; reflection into host
   #"\bfs\b.*require|require.*\bfs\b" ; node fs require
   #"\bprocess\.env\b"         ; ambient env access
   #"\bchild_process\b"        ; subprocess
   #"\bjs/"                    ; cljs host interop (js/parseInt and friends)
   #"#js[\s\[\{]"              ; cljs #js literal
   #"\bjs\*"                   ; cljs js* reader-level host interop
   #"\bgoog\."                 ; Closure libs — cljs-only, breaks JVM .cljc
   #"\(\.[-a-zA-Z]"            ; (.method obj) / (.-field obj) member access
   #"\([A-Z][a-zA-Z0-9]*/"     ; JVM static-call interop (Integer/parseInt,
                               ; Runtime/getRuntime ...) — the JVM-side twin of
                               ; the js/parseInt hole PR #20 closed; anchored in
                               ; call position so docstring prose like
                               ; "Scan/pkt/http" is not flagged
   #"\(\.\."])                 ; (.. obj (method)) dot-dot macro — (\.\. is
                               ; missed by the [-a-zA-Z] class above)

(deftest pure-cljc-static-test
  (doseq [f src-files]
    (let [src (read-src f)]
      (doseq [re forbidden]
        (is (not (re-find re src))
            (str f " contains forbidden effect form: " re))))))

(deftest cljc-extension-test
  (doseq [f src-files]
    (is (str/ends-with? f ".cljc") (str f " must be .cljc"))))

;; discovery sanity: the derived list must cover the known namespaces, so a
;; broken readdir (empty list) cannot silently make the checks above vacuous
(deftest src-discovery-covers-known-namespaces-test
  (is (set/subset? #{"src/sec/scan.cljc" "src/sec/pkt.cljc"
                     "src/sec/http.cljc" "src/sec/io.cljc"}
                   (set src-files))
      "src file discovery must include the known production namespaces"))

;; Positive control: one violator example per forbidden effect form — legal
;; Clojure that would nonetheless break the pure-.cljc contract. If a pattern
;; stops matching its own example, the blind spot fails loudly here instead of
;; letting a real violation through pure-cljc-static-test (the pre-#20
;; js/parseInt failure mode: the guard existed but had no such example).
(def violators
  [["file slurp"          "(def s (slurp \"capture.pcap\"))"]
   ["clojure.java.io"     "(import 'clojure.java.io)"]
   ["System interop"      "(def os (System/getProperty \"os.name\"))"]
   ["java namespace"      "(import 'java.io.File)"]
   ["host reflection"     "(defn bad [m] (.invoke m nil))"]
   ["node fs require"     "(def fs (require 'fs))"]
   ["process.env"         "(def e process.env.SECRET)"]
   ["child_process"       "(def cp (require 'child_process))"]
   ["js/ interop"         "(def n (js/parseInt x 10))"]
   ["#js literal"         "(def x #js {:a 1})"]
   ["js* reader"          "(def x (js* \"1 + 1\"))"]
   ["goog Closure ns"     "(require '[goog.string :as gstr])"]
   ["(.method obj)"       "(defn f [s] (.charAt s 0))"]
   ["(.-field obj)"       "(def p (.-pathname url))"]
   ["JVM static call"     "(def n (Integer/parseInt \"3\"))"]
   ["Runtime exec"        "(def r (Runtime/getRuntime))"]
   ["dot-dot macro"       "(def s (.. Thread/currentThread (getName)))"]])

(deftest forbidden-guard-detects-violators-test
  (doseq [[label src] violators]
    (is (some #(re-find % src) forbidden)
        (str "guard must detect forbidden effect form: " label))))

;; Negative control: idiomatic pure .cljc code must not be flagged, so the
;; patterns cannot be "fixed" into a sledgehammer that fails real sources
;; (destructuring, bit ops, 0xff literals, #?{} reader conditionals).
;; The last two entries pin the Uppercase/slash false-positive class: docstring
;; prose in the real src (sec.scan \"Port/host scanner\", sec.io
;; \"Scan/pkt/http logic\") contains Caps/slash text that call-position
;; anchoring must NOT flag.
(def clean-forms
  ["(ns sec.pkt\n  (:require [clojure.string :as str] [sec.io :as io]))"
   "(defn classify [x] (cond (= x 1) :open :else :closed))"
   "(defn word [b o] (bit-and (bit-shift-right (aget b o) 8) 0xff))"
   "(let [{:keys [a b]} m] (str a \"-\" b))"
   "(def platform (if (= :clj *platform*) :jvm :node))"
   "(#?(:clj 1 :cljs 2))"
   "(ns sec.scan\n  \"Port/host scanner — the nmap equivalent slice.\")"
   "  Scan/pkt/http logic never opens sockets or captures packets directly."])

(deftest forbidden-guard-clean-forms-test
  (doseq [src clean-forms]
    (is (not-any? #(re-find % src) forbidden)
        (str "clean pure form must not be flagged: " src))))
