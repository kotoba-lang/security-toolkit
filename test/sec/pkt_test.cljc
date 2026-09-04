(ns sec.pkt-test
  (:require [clojure.test :refer [deftest is testing]]
            [sec.pkt :as pkt]))

(defn- byte-array* [coll] (into-array (map int coll)))

(defn- eth+ipv4+tcp-bytes
  "Build one minimal Ethernet/IPv4/TCP frame (SYN to 10.0.0.2:80 from 10.0.0.1)."
  []
  (let [eth [0x00 0x11 0x22 0x33 0x44 0x55   ; dst mac
             0x66 0x77 0x88 0x99 0xaa 0xbb   ; src mac
             0x08 0x00]                       ; IPv4
        ;; IPv4 header, 20 bytes, ihl 5, proto 6 (TCP)
        ip [0x45 0x00 0x00 0x28               ; version/ihl, tos, total len 40
            0x00 0x01 0x00 0x00               ; id, flags/frag
            0x40 0x06 0x00 0x00               ; ttl 64, proto 6, checksum 0
            10 0 0 1                          ; src 10.0.0.1
            10 0 0 2]                         ; dst 10.0.0.2
        ;; TCP header, 20 bytes: src 4444 dst 80, seq 1 ack 1, offset 5, SYN
        tcp [0x11 0x5c 0x00 0x50
             0x00 0x00 0x00 0x01
             0x00 0x00 0x00 0x01
             0x50 0x02
             0x20 0x00                        ; window
             0x00 0x00 0x00 0x00]]
    (byte-array* (concat eth ip tcp))))

(defn- pcap-wrap
  "Wrap one frame into classic little-endian pcap bytes."
  [frame-bytes]
  (let [n (count frame-bytes)
        le32 (fn [v] [(bit-and v 0xff) (bit-and (bit-shift-right v 8) 0xff)
                      (bit-and (bit-shift-right v 16) 0xff) (bit-and (bit-shift-right v 24) 0xff)])
        hdr (concat [0xd4 0xc3 0xb2 0xa1]   ; magic LE
                    (le32 2) (le32 0)        ; version 2.4
                    (le32 0) (le32 262144)   ; thiszone, snaplen
                    (le32 1))                ; linktype Ethernet
        rec (concat (le32 1700000000) (le32 123456)
                    (le32 n) (le32 n))]
    (byte-array* (concat hdr rec frame-bytes))))

(deftest hex-test
  (is (= "0800" (#'pkt/hex 0x0800 4)))
  (is (= "00" (#'pkt/hex 0 2))))

(deftest dissect-frame-test
  (let [f (pkt/dissect-frame (eth+ipv4+tcp-bytes))]
    (is (= "00:11:22:33:44:55" (get-in f [:eth :dst])))
    (is (= "66:77:88:99:aa:bb" (get-in f [:eth :src])))
    (is (= "IPv4" (get-in f [:eth :ethertype-name])))
    (is (= "10.0.0.1" (get-in f [:ip :src])))
    (is (= "10.0.0.2" (get-in f [:ip :dst])))
    (is (= "TCP" (get-in f [:ip :protocol])))
    (is (= 80 (get-in f [:l4 :dst-port])))
    (is (= 4444 (get-in f [:l4 :src-port])))
    (is (get-in f [:l4 :flags :syn]))
    (is (not (get-in f [:l4 :flags :ack])))))

(deftest dissect-pcap-test
  (let [frames (pkt/dissect-pcap (pcap-wrap (eth+ipv4+tcp-bytes)))]
    (is (= 1 (count frames)))
    (let [f (first frames)]
      (is (= 1 (:frame f)))
      (is (= 1700000000 (:ts-sec f)))
      (is (= 80 (get-in f [:l4 :dst-port]))))))

(deftest not-pcap-test
  (is (thrown-with-msg? js/Error #"not a pcap"
        (pkt/dissect-pcap (byte-array* [1 2 3 4 5 6 7 8])))))
