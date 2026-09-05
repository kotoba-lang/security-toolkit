(ns sec.pure-cljc-test
  "Conformance ⑤: static check that production sources stay pure `.cljc`.
  No ambient authority / host-only effects in src/: slurp, JVM interop,
  clojure.java.io, or clj-only requires. (ADR-2609051100)."
  (:require [clojure.test :refer [deftest is]]
            [clojure.string :as str]))

;; nbb test runner: reading src files here is test-side only; production
;; sources themselves must contain none of these effect forms.
(def fs (js/require "fs"))

(def src-files
  ["src/sec/scan.cljc" "src/sec/pkt.cljc" "src/sec/http.cljc" "src/sec/io.cljc"])

(defn- read-src [path]
  (.readFileSync fs path "utf8"))

(def forbidden
  [#"slurp"                    ; file I/O
   #"clojure\.java\.io"        ; clj-only I/O namespace
   #"\bSystem\."               ; JVM interop
   #"java\.(io|net|lang)\."    ; JVM namespace interop
   #"\.getMethod\b|\.invoke\b" ; reflection into host
   #"\bfs\b.*require|require.*\bfs\b" ; node fs require
   #"\bprocess\.env\b"         ; ambient env access
   #"\bchild_process\b"])      ; subprocess

(deftest pure-cljc-static-test
  (doseq [f src-files]
    (let [src (read-src f)]
      (doseq [re forbidden]
        (is (not (re-find re src))
            (str f " contains forbidden effect form: " re))))))

(deftest cljc-extension-test
  (doseq [f src-files]
    (is (str/ends-with? f ".cljc") (str f " must be .cljc"))))
