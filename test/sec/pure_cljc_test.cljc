(ns sec.pure-cljc-test
  "Conformance ⑤: static check that production sources stay pure `.cljc`.
  No ambient authority / host-only effects in src/: slurp, JVM interop,
  clojure.java.io, or clj-only requires. (ADR-2609051100)."
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

;; discovery sanity: the derived list must cover the known namespaces, so a
;; broken readdir (empty list) cannot silently make the checks above vacuous
(deftest src-discovery-covers-known-namespaces-test
  (is (set/subset? #{"src/sec/scan.cljc" "src/sec/pkt.cljc"
                     "src/sec/http.cljc" "src/sec/io.cljc"}
                   (set src-files))
      "src file discovery must include the known production namespaces"))
