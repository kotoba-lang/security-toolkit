(ns sec.scan-test
  (:require [clojure.test :refer [deftest is testing]]
            [sec.scan :as scan]
            [sec.http :as http]
            [sec.io :as io]
            [sec.io.fake :as fake]))

(def p (fake/fake-provider {:responses {"example.com:80" "HTTP/1.1 200 OK\r\n\r\nhi"}
                            :refused #{22}
                            :silent #{443}}))

(deftest classify-connect-test
  (is (= :open (scan/classify-connect {:ok true})))
  (is (= :closed (scan/classify-connect {:refused true})))
  (is (= :filtered (scan/classify-connect {:timeout true})))
  (is (= :filtered (scan/classify-connect {:unreachable true})))
  (is (= :unknown (scan/classify-connect {}))))

(deftest plan-test
  (is (= [{:host "a" :port 22} {:host "a" :port 80}
          {:host "b" :port 22} {:host "b" :port 80}]
         (scan/plan {:hosts ["a" "b"] :ports [80 22]}))))

(deftest provider-required-test
  (is (thrown-with-msg? js/Error #"provider" (scan/connect-scan {:hosts ["h"] :ports [1]} {}))))

(deftest connect-scan-test
  (let [rs (scan/connect-scan {:hosts ["example.com"] :ports [80 22 443]}
                              {:provider p})]
    (is (= {:host "example.com" :port 80 :state :open}
           (first (scan/open-ports rs))))
    (is (= :closed (:state (first (filter #(= 22 (:port %)) rs)))))
    (is (= :filtered (:state (first (filter #(= 443 (:port %)) rs)))))))

(deftest host-sweep-test
  (let [rs (scan/host-sweep {:hosts ["example.com"] :ports [80 22 443]} {:provider p})]
    (is (= [{:host "example.com" :alive? true}] rs))))

(deftest provider-guard-test
  (is (thrown-with-msg? js/Error #"authority-free" (io/provider! {}))))

;; conformance ①: EVERY entry point must deny when no :provider is given
;; (seam enforcement is not just connect-scan's job).
(deftest provider-deny-all-entry-points-test
  (let [spec {:hosts ["h"] :ports [1]}]
    (doseq [[name thunk]
            [["sec.scan/connect-scan" #(scan/connect-scan spec {})]
             ["sec.scan/host-sweep"   #(scan/host-sweep spec {})]
             ["sec.http/send-request" #(http/send-request
                                        {:method "GET" :path "/" :headers {} :body ""}
                                        {:host "h"})]]]
      (is (thrown-with-msg? js/Error #"provider" (thunk))
          (str name " must deny without :provider")))))
