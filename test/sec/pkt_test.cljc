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
             0x50 0x02 0x20 0x00]
        payload []]
    (byte-array* (concat eth ip tcp))))

(defn- pcap-wrap
  "Wrap one frame into classic pcap bytes. :endian :little (default) or :big.
   :linktype overrides the global-header linktype (default 1 = Ethernet);
   :magic overrides the 4-byte magic number."
  [frame-bytes & [{:keys [endian magic linktype] :or {endian :little linktype 1}}]]
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
                    (w32 linktype))               ; linktype (1 = Ethernet)
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

;; golden: nanosecond-variant magic (4d 3c b2 a1, LE) must be dissected with
;; :ts-unit :ns so consumers don't do 1000x-off wall-clock math (issue #9)
(deftest dissect-pcap-nanosecond-golden-test
  (let [frame (eth+ipv4+tcp-bytes)
        pc (pcap-wrap frame {:magic [0x4d 0x3c 0xb2 0xa1]})
        f (first (pkt/dissect-pcap pc))]
    (is (= "4d 3c b2 a1" (#'pkt/bytes->hex pc 0 4)))
    (is (= 1700000000 (:ts-sec f)))
    (is (= 123456 (:ts-usec f)))
    (is (= :ns (:ts-unit f)))
    (is (= "10.0.0.2" (get-in f [:ip :dst])))
    (is (= 80 (get-in f [:l4 :dst-port])))
    ;; classic files keep :ts-unit :us
    (is (= :us (:ts-unit (first (pkt/dissect-pcap (pcap-wrap frame {:endian :little}))))))
    (is (= :us (:ts-unit (first (pkt/dissect-pcap (pcap-wrap frame {:endian :big}))))))))

;; golden: BE nanosecond-variant magic (a1 b2 3c 4d) shares its first two
;; bytes with classic BE (a1 b2 c3 d4) — must classify :endian :big with
;; :ts-unit :ns and dissect the frame as BE, not fall through to classic BE
;; with the frame bytes read little-endian (issue #15)
(defn- pcap-wrap-be-ns
  "Wrap one frame into a big-endian nanosecond-variant pcap container."
  [frame-bytes]
  (let [n (count frame-bytes)
        le32 (fn [v] [(bit-and v 0xff) (bit-and (bit-shift-right v 8) 0xff)
                      (bit-and (bit-shift-right v 16) 0xff) (bit-and (bit-shift-right v 24) 0xff)])
        be32 (fn [v] (reverse (le32 v)))
        hdr (concat [0xa1 0xb2 0x3c 0x4d]        ; magic BE ns
                    (be32 2) (be32 0)            ; version 2.4
                    (be32 0) (be32 262144)       ; thiszone, snaplen
                    (be32 1))                    ; linktype Ethernet
        rec (concat (be32 1700000000) (be32 123456)
                    (be32 n) (be32 n))]
    (byte-array* (concat hdr rec frame-bytes))))

(deftest dissect-pcap-big-endian-nanosecond-golden-test
  (let [frame (eth+ipv4+tcp-bytes)
        pc (pcap-wrap-be-ns frame)
        f (first (pkt/dissect-pcap pc))]
    (is (= "a1 b2 3c 4d" (#'pkt/bytes->hex pc 0 4)))
    (is (= 1700000000 (:ts-sec f)))
    (is (= 123456 (:ts-usec f)))
    (is (= :ns (:ts-unit f)))
    (is (= "10.0.0.1" (get-in f [:ip :src])))
    (is (= "10.0.0.2" (get-in f [:ip :dst])))
    (is (= "TCP" (get-in f [:ip :protocol])))
    (is (= 4444 (get-in f [:l4 :src-port])))
    (is (= 80 (get-in f [:l4 :dst-port])))
    (is (get-in f [:l4 :flags :syn]))
    ;; classic BE (a1 b2 c3 d4) must still classify :ts-unit :us
    (is (= :us (:ts-unit (first (pkt/dissect-pcap (pcap-wrap frame {:endian :big}))))))))

;; UDP golden fixture (issue #5)

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
    (is (= "beef" (get-in f [:l4 :checksum])))
    ;; stored beef is arbitrary (not the RFC 768 checksum of this segment) —
    ;; verification must say so instead of silently passing (issue #18)
    (is (false? (get-in f [:l4 :checksum-valid])))))

;; conformance (issue #18): a frame whose stored checksum is the real RFC 768
;; checksum over pseudo-header + segment must verify :checksum-valid true,
;; and a corrupted segment must flip it to false.
(deftest udp-checksum-verification-test
  (let [build (fn [checksum16]
                (let [eth [0x00 0x11 0x22 0x33 0x44 0x55
                           0x66 0x77 0x88 0x99 0xaa 0xbb
                           0x08 0x00]
                      ip [0x45 0x00 0x00 0x20
                          0x00 0x01 0x00 0x00
                          0x40 0x11 0x00 0x00
                          10 0 0 1
                          10 0 0 2]
                      udp [0x14 0xe9 0x00 0x35
                           0x00 0x0c
                           (bit-and (bit-shift-right checksum16 8) 0xff)
                           (bit-and checksum16 0xff)]
                      payload [0xde 0xad 0x01 0x02]]
                  (byte-array* (concat eth ip udp payload))))
        ;; compute with checksum field zero-filled, then rebuild with the value
        zero (build 0)
        c (pkt/compute-udp-checksum zero 14 (+ 14 20))
        good (build c)
        bad (build c)]
    (aset bad (+ 14 20 8 1) (int 0xff))   ; corrupt 2nd payload byte, keep checksum
    (let [f-good (pkt/dissect-frame good)
          f-bad (pkt/dissect-frame bad)]
      (is (true? (get-in f-good [:l4 :checksum-valid]))
          "stored == computed RFC 768 checksum must verify")
      (is (= 12 (get-in f-good [:l4 :length])))
      (is (false? (get-in f-bad [:l4 :checksum-valid]))
          "corrupted segment must fail verification"))))

;; RFC 768: stored 0x0000 means 'sender did not compute' — report invalid,
;; never fabricate a pass (issue #18)
(deftest udp-checksum-zero-stored-test
  (let [b (eth+ipv4+udp-bytes)]
    (aset b (+ 14 20 6) (int 0))
    (aset b (+ 14 20 7) (int 0))
    (let [f (pkt/dissect-frame b)]
      (is (= "0000" (get-in f [:l4 :checksum])))
      (is (false? (get-in f [:l4 :checksum-valid]))))))

;; pcap level: :checksum-valid flows through dissect-pcap
(deftest dissect-pcap-udp-checksum-test
  (let [f (first (pkt/dissect-pcap (pcap-wrap (eth+ipv4+udp-bytes))))]
    (is (contains? (:l4 f) :checksum-valid))
    (is (false? (:checksum-valid (:l4 f))))))

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

;; conformance ③ (rejection side): dissect-pcap is Ethernet-only for now, so a
;; valid-magic pcap with an unsupported linktype must be rejected LOUDLY with
;; ex-info {:kind ::pkt/linktype} — both endiannesses, common real-world link
;; types (0 NULL, 12 RAW, 101/113 IEEE802, 276 Solaris IPNET) — and the
;; rejection must carry the actual linktype in ex-data. Silently dissecting
;; non-Ethernet bytes as Ethernet (or NPE'ing) is the failure mode pinned out
;; here. Linktype is read with the file's endianness, so BE files must reject
;; too.
(deftest dissect-pcap-unsupported-linktype-test
  (doseq [endian [:little :big]
          lt     [0 12 101 113 276]]
    (let [pc (pcap-wrap (eth+ipv4+tcp-bytes) {:endian endian :linktype lt})
          err (try
                (pkt/dissect-pcap pc)
                (catch :default e e))]
      (is (instance? js/Error err)
          (str endian " linktype " lt " must throw, not dissect"))
      (is (= :sec.pkt/linktype (:kind (ex-data err)))
          (str endian " linktype " lt " must throw ex-info with :kind :sec.pkt/linktype"))
      (is (= lt (:linktype (ex-data err)))
          (str endian " linktype " lt " must carry the actual linktype in ex-data"))))
  ;; positive control: linktype 1 (Ethernet) still parses through the same
  ;; builder — the guard rejects others, not everything
  (is (= 1 (count (pkt/dissect-pcap
                   (pcap-wrap (eth+ipv4+tcp-bytes) {:linktype 1}))))
      "linktype 1 must remain accepted via the same pcap-wrap path"))
