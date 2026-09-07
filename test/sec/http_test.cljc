(ns sec.http-test
  (:require [clojure.test :refer [deftest is testing]]
            [sec.http :as http]
            [sec.io.fake :as fake]))

(deftest parse-request-test
  (let [r (http/parse-request "GET /a?b=1 HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n")]
    (is (= "GET" (:method r)))
    (is (= "/a?b=1" (:path r)))
    (is (= "HTTP/1.1" (:version r)))
    (is (= "example.com" (get-in r [:headers "host"])))
    (is (= "text/html" (get-in r [:headers "accept"])))
    (is (= "" (:body r)))))

(deftest parse-request-dup-headers-test
  (let [r (http/parse-request "GET / HTTP/1.1\r\nX-A: 1\r\nX-A: 2\r\n\r\n")]
    (is (= ["1" "2"] (get-in r [:headers "x-a"])))))

(deftest parse-response-test
  (let [r (http/parse-response "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")]
    (is (= 404 (:status r)))
    (is (= "Not Found" (:reason r)))))

(deftest mutate-and-render-test
  (let [raw "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"
        r (-> raw http/parse-request (http/set-body "goodbye"))]
    (is (= "goodbye" (:body r)))
    (is (= "7" (get-in r [:headers "content-length"])))
    (let [out (http/render-request r)]
      (is (re-find #"POST /api HTTP/1.1" out))
      (is (re-find #"content-length: 7" out))
      (is (re-find #"\r\n\r\ngoodbye$" out)))))

;; conformance ④: parse→render→reparse round-trip must preserve everything,
;; including repeated same-name headers (vector values) and the body.
(deftest render-reparse-roundtrip-test
  (let [raw "POST /api HTTP/1.1\r\nHost: example.com\r\nX-Tag: one\r\nX-Tag: two\r\nX-Tag: three\r\nContent-Length: 5\r\n\r\nhello"
        p1 (http/parse-request raw)
        p2 (http/parse-request (http/render-request p1))]
    (is (= p1 p2))
    (is (= ["one" "two" "three"] (get-in p2 [:headers "x-tag"])))
    (is (= "hello" (:body p2)))
    ;; mutating one entry of a repeated header keeps the others on the wire
    (let [m (assoc-in p1 [:headers "x-tag"] ["one" "CHANGED" "three"])
          p3 (http/parse-request (http/render-request m))]
      (is (= ["one" "CHANGED" "three"] (get-in p3 [:headers "x-tag"])))
      (is (= "hello" (:body p3))))))

(deftest set-header-test
  (let [r (-> (http/parse-request "GET / HTTP/1.1\r\nHost: a.com\r\n\r\n")
              (http/set-header "Host" "b.com"))]
    (is (= "b.com" (get-in r [:headers "host"])))))

(deftest send-request-test
  (let [p (fake/fake-provider {:responses {"example.com:80" "HTTP/1.1 200 OK\r\nX-Tag: t\r\n\r\nok"}})
        req (http/parse-request "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        resp (http/send-request req {:provider p :host "example.com" :port 80})]
    (is (= 200 (:status resp)))
    (is (= "t" (get-in resp [:headers "x-tag"])))
    (is (= "ok" (:body resp)))))

;; conformance ⑤ (js interop removal): parse-status-code is a pure 3-digit
;; decimal reader that replaces the js/parseInt in parse-response. Pins the
;; stricter-than-js semantics the old builtin leaked: garbage -> nil (no NaN),
;; hex -> nil (js gave 16), "+2xx" -> nil (js gave 2), non-3-digit -> nil.
(deftest parse-status-code-pure-test
  (is (= 200 (http/parse-status-code "200")))
  (is (= 404 (http/parse-status-code "404")))
  (is (= 500 (http/parse-status-code "500")))
  (is (= 100 (http/parse-status-code "100")))
  (is (nil? (http/parse-status-code "garbage")))
  (is (nil? (http/parse-status-code "0x10")))
  (is (nil? (http/parse-status-code "+2xx")))
  (is (nil? (http/parse-status-code "10")))
  (is (nil? (http/parse-status-code "1000")))
  (is (nil? (http/parse-status-code "2 0")))
  (is (nil? (http/parse-status-code "-1x")))
  (is (nil? (http/parse-status-code nil)))
  (is (nil? (http/parse-status-code 200))))

;; parse-response end-to-end through the pure reader: malformed status lines
;; surface as nil status instead of a NaN (or a hex/prefix artifact) leaking
;; into downstream EDN.
(deftest parse-response-status-purity-test
  (let [ok (http/parse-response "HTTP/1.1 418 I'm a teapot\r\n\r\n")]
    (is (= 418 (:status ok)))
    (is (= "I'm a teapot" (:reason ok))))
  (let [junk (http/parse-response "HTTP/1.1 garbage Here\r\n\r\n")]
    (is (nil? (:status junk))
        "malformed status must be nil, never a NaN number")
    (is (not (number? (:status junk)))))
  (let [hex (http/parse-response "HTTP/1.1 0x10 x\r\n\r\n")]
    (is (nil? (:status hex))
        "hex status must not be silently parsed as 16 (js/parseInt behavior)"))
  (let [neg (http/parse-response "HTTP/1.1 -1 x\r\n\r\n")]
    (is (nil? (:status neg)))))

;; conformance ① (seam enforcement, wire layer): the ONLY effect of
;; send-request is the bytes handed to the provider's send-bytes — so far
;; the seam was only guarded for "provider present" (deny tests), never for
;; "what actually crosses it". fake/recorded-requests now reads back the
;; provider's send log (previously a nil-returning stub). Pins that exactly
;; one request crosses the seam, the request's own Host header survives the
;; host-hdr override in send-request, repeated headers stay repeated, and
;; re-parsing the recorded wire recovers the original EDN — a render that
;; never reaches the provider, or reaches it mangled, fails here.
(deftest send-request-wire-bytes-test
  (let [pf (fake/fake-provider {:responses {"h:80" "HTTP/1.1 200 OK\r\n\r\nok"}})
        raw "GET /x HTTP/1.1\r\nHost: original\r\nX-Tag: a\r\nX-Tag: b\r\nContent-Length: 4\r\n\r\nbody"
        req (http/parse-request raw)
        resp (http/send-request req {:provider pf :host "h" :port 80})
        sent (fake/recorded-requests pf)]
    (is (= 200 (:status resp)))
    (is (= 1 (count sent)) "exactly one request must cross the seam")
    (let [wire (:bytes (first sent))
          reparsed (http/parse-request wire)]
      (is (= req reparsed)
          "re-parsing the recorded wire bytes must recover the original request EDN")
      (is (= "original" (get-in reparsed [:headers "host"]))
          "the request's own Host header wins over opts :host (current send-request contract)")
      (is (= ["a" "b"] (get-in reparsed [:headers "x-tag"])))
      (is (= "body" (:body reparsed)))
      (is (re-find #"\r\n\r\nbody$" wire)))))
