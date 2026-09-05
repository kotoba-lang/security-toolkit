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
  "Wrap one frame into classic pcap bytes. :endian :little (default) or :big."
  [frame-bytes & [{:keys [endian magic] :or {endian :little}}]]
  (let [n (count frame-bytes)
        le32 (fn [v] [(bit-and v 0xff) (bit-and (bit-shift-right v 8) 0xff)
                      (bit-and (bit-shift-right v 16) 0xff) (bit-and (bit-shift-right v 24) 0xff)])
        be32 (fn [v] (reverse (le32 v)))
        w32 (if (= endian :big) be32 le32)
        hdr (concat (or magic
                        (if (= endian :big)
                          [0xa1 0xb2 0xc3 0xd4]   ; magic BE
                          [0xd4 0xc3 0xb2 0xa1])) ; magic LE
                    (w32 2) (w32 0)               ; version 2.4
                    (w32 0) (w32 262144)          ; thiszone, snaplen
                    (w32 1))                      ; linktype Ethernet
        rec (concat (w32 1700000000) (w32 123456)
                    (w32 n) (w32 n))]
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

;; golden fixture: same frame, big-endian pcap container must dissect identically
(deftest dissect-pcap-big-endian-golden-test
  (let [frame (eth+ipv4+tcp-bytes)
        le (first (pkt/dissect-pcap (pcap-wrap frame {:endian :little})))
        be (first (pkt/dissect-pcap (pcap-wrap frame {:endian :big})))]
    (is (= "a1 b2 c3 d4" (#'pkt/bytes->hex (pcap-wrap frame {:endian :big}) 0 4)))
    (is (= (dissoc le :caplen :origlen)
           (dissoc be :caplen :origlen)))
    (is (= 1700000000 (:ts-sec be)))
    (is (= 123456 (:ts-usec be)))
    (is (= "10.0.0.2" (get-in be [:ip :dst])))
    (is (= 80 (get-in be [:l4 :dst-port])))
    (is (get-in be [:l4 :flags :syn]))))

(deftest not-pcap-test
  (is (thrown-with-msg? js/Error #"not a pcap"
        (pkt/dissect-pcap (byte-array* [1 2 3 4 5 6 7 8])))))

;; golden: wrong magic on a otherwise-valid file must be rejected
(deftest not-pcap-bad-magic-test
  (is (thrown-with-msg? js/Error #"not a pcap"
        (pkt/dissect-pcap (pcap-wrap (eth+ipv4+tcp-bytes) {:magic [0xde 0xad 0xbe 0xef]})))))

;; ── UDP golden fixture (issue #5) ────────────────────────────────────────

(defn- eth+ipv4+udp-bytes
  "Minimal Ethernet/IPv4/UDP frame: 10.0.0.1:5353 -> 10.0.0.2:53, 4-byte payload."
  []
  (let [eth [0x00 0x11 0x22 0x33 0x44 0x55
             0x66 0x77 0x88 0x99 0xaa 0xbb
             0x08 0x00]
        ;; IPv4 header, 20 bytes, ihl 5, proto 17 (UDP), total len 32
        ip [0x45 0x00 0x00 0x20
            0x00 0x01 0x00 0x00
            0x40 0x11 0x00 0x00
            10 0 0 1
            10 0 0 2]
        ;; UDP header, 8 bytes: src 5353 dst 53, length 12 (8 hdr + 4 payload)
        udp [0x14 0xe9 0x00 0x35
             0x00 0x0c 0xbe 0xef]
        payload [0xde 0xad 0x01 0x02]]
    (byte-array* (concat eth ip udp payload))))

(deftest dissect-udp-golden-test
  (let [f (pkt/dissect-frame (eth+ipv4+udp-bytes))]
    (is (= "UDP" (get-in f [:ip :protocol])))
    (is (= "10.0.0.1" (get-in f [:ip :src])))
    (is (= 5353 (get-in f [:l4 :src-port])))
    (is (= 53 (get-in f [:l4 :dst-port])))
    ;; UDP length = header (8) + payload (4)
    (is (= 12 (get-in f [:l4 :length])))
    ;; checksum renders as 4-digit hex string
    (is (= "beef" (get-in f [:l4 :checksum])))))

(deftest dissect-pcap-udp-golden-test
  (let [f (first (pkt/dissect-pcap (pcap-wrap (eth+ipv4+udp-bytes))))]
    (is (= 1 (:frame f)))
    (is (= "UDP" (get-in f [:ip :protocol])))
    (is (= 53 (get-in f [:l4 :dst-port])))))

;; mixed pcap: one TCP frame followed by one UDP frame, each with correct :l4
(deftest dissect-pcap-mixed-tcp-udp-test
  (let [hdr  (take 24 (seq (pcap-wrap (eth+ipv4+tcp-bytes))))
        recs (mapcat #(drop 24 (seq (pcap-wrap %)))
                     [(eth+ipv4+tcp-bytes) (eth+ipv4+udp-bytes)])
        pcap (byte-array* (concat hdr recs))
        frames (pkt/dissect-pcap pcap)]
    (is (= 2 (count frames)))
    (is (= "TCP" (get-in (first frames) [:ip :protocol])))
    (is (= 80 (get-in (first frames) [:l4 :dst-port])))
    (is (= "UDP" (get-in (second frames) [:ip :protocol])))
    (is (= 53 (get-in (second frames) [:l4 :dst-port])))))
