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
