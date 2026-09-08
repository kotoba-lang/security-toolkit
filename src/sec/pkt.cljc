(ns sec.pkt
  "pcap reading + protocol dissection — the wireshark equivalent slice.

  Pure `.cljc`. Parses pcap file format (classic, little/big endian) and
  dissects Ethernet / IPv4 / TCP / UDP into plain EDN maps.
  Raw capture (live sniffing) is out of scope here — provider seam only;
  this namespace consumes already-captured bytes (ADR-2609051100)."
  (:require [clojure.string :as str]))

;; ── byte helpers ────────────────────────────────────────────────────────
(defn- u8  [b off] (aget b off))
(defn- u16be [b off] (+ (* (aget b off) 256) (aget b (inc off))))
(defn- u32be [b off] (let [a (u8 b off) bb (u8 b (inc off)) c (u8 b (+ off 2)) d (u8 b (+ off 3))]
                       (+ (* a 16777216) (* bb 65536) (* c 256) d)))
(defn- hex
  ([n] (hex n 2))
  ([n width]
   (let [digits "0123456789abcdef"]
     (loop [acc "" n (bit-and n 0xFFFFFFFF) c 0]
       (if (= c width)
         acc
         (recur (str (nth digits (bit-and n 15)) acc)
                (bit-shift-right n 4) (inc c)))))))

(defn bytes->hex
  "Format bytes as wireshark-style hex string."
  [b off len]
  (str/join " " (map #(hex (aget b (+ off %)) 2) (range len))))

(defn- mac-str [b off]
  (str/join ":" (map #(hex (aget b (+ off %)) 2) (range 6))))

(defn- ipv4-str [b off]
  (str/join "." (map #(aget b (+ off %)) (range 4))))

;; ── pcap global header ──────────────────────────────────────────────────

(defn- parse-global-header
  [b]
  ;; magic detection is done in detect-endianness; kept for clarity
  (bytes->hex b 0 4))

(defn- detect-endianness
  [b]
  ;; returns {:endian ... :ts-unit :us|:ns} — :ts-unit follows the pcap magic
  ;; 4-byte magic must match exactly: a1 b2 c3 d4 (BE us) vs a1 b2 3c 4d
  ;; (BE ns, issue #15) share the first two bytes — check ns BE first.
  (let [m0 (u8 b 0) m1 (u8 b 1)]
    (cond
      (and (= m0 0xd4) (= m1 0xc3)) {:endian :little :ts-unit :us}
      (and (= m0 0xa1) (= m1 0xb2) (= (u8 b 2) 0x3c) (= (u8 b 3) 0x4d))
      {:endian :big :ts-unit :ns}
      (and (= m0 0xa1) (= m1 0xb2)) {:endian :big    :ts-unit :us}
      (and (= m0 0x4d) (= m1 0x3c)) {:endian :little :ts-unit :ns} ; nanosecond LE
      :else (throw (ex-info "not a pcap file" {:kind ::not-pcap :magic (bytes->hex b 0 4)})))))

;; ── frame parsing ───────────────────────────────────────────────────────

(defn- dissect-ethernet
  [b off]
  {:dst (mac-str b off)
   :src (mac-str b (+ off 6))
   :ethertype (u16be b (+ off 12))
   :ethertype-name (case (u16be b (+ off 12))
                     0x0800 "IPv4"
                     0x86dd "IPv6"
                     0x0806 "ARP"
                     (hex (u16be b (+ off 12)) 4))})

(defn- dissect-ipv4
  [b off]
  (let [ihl (* (mod (u8 b off) 16) 4)
        total-len (u16be b (+ off 2))
        proto (u8 b (+ off 9))
        proto-name (case proto
                     6 "TCP" 17 "UDP" 1 "ICMP"
                     (str "proto-" proto))]
    {:version (int (/ (u8 b off) 16))
     :ihl ihl
     :total-length total-len
   :ttl (u8 b (+ off 8))
   :protocol proto-name
   :src (ipv4-str b (+ off 12))
   :dst (ipv4-str b (+ off 16))}))

(defn- dissect-tcp
  [b off]
  {:src-port (u16be b off)
   :dst-port (u16be b (+ off 2))
   :seq (u32be b (+ off 4))
   :ack (u32be b (+ off 8))
   :data-offset (* (int (/ (u8 b (+ off 12)) 16)) 4)
   :flags {:syn (pos? (bit-and (u8 b (+ off 13)) 0x02))
           :ack (pos? (bit-and (u8 b (+ off 13)) 0x10))
           :fin (pos? (bit-and (u8 b (+ off 13)) 0x01))
           :rst (pos? (bit-and (u8 b (+ off 13)) 0x04))}
   :window (u16be b (+ off 14))})

(defn compute-udp-checksum
  "RFC 768 checksum over the IPv4 pseudo-header (src/dst IP, proto 17, UDP
  length) + UDP segment. `b` is the whole frame, `ip-off` the IPv4 header
  start, `udp-off` the UDP segment start. Pure byte arithmetic; returns the
  16-bit checksum as a sender would compute it (issue #18)."
  [b ip-off udp-off]
  (let [udp-len (u16be b (+ udp-off 4))
        words (fn [off len]
                (let [n (quot len 2)]
                  (concat
                   (map (fn [i] (+ (* (aget b (+ off (* 2 i))) 256)
                                   (aget b (+ off (inc (* 2 i))))))
                        (range n))
                   (when (odd? len)
                     [(* (aget b (+ off (* 2 n))) 256)]))))
        pseudo (concat (words (+ ip-off 12) 8)      ; src + dst IP
                       [0x0011 udp-len])            ; proto 17, udp length
        ;; RFC 768 computes with the checksum field zero-filled: read the
        ;; segment but force bytes udp-off+6/+7 to 0 (stored value excluded)
        seg-words (map (fn [i]
                         (let [o (+ udp-off (* 2 i))]
                           (cond
                             (= o (+ udp-off 6)) 0
                             (= o (+ udp-off 7)) 0
                             :else (+ (* (aget b o) 256)
                                      (aget b (inc o))))))
                       (range (quot udp-len 2)))
        seg-tail (when (odd? udp-len)
                   [(* (aget b (+ udp-off (- udp-len 1))) 256)])
        total (reduce + 0 (concat pseudo seg-words seg-tail))]
    ;; fold carries until < 0x10000, then 1's-complement
    (loop [s total]
      (if (> s 0xFFFF)
        (recur (bit-and (+ (bit-and s 0xFFFF) (bit-shift-right s 16)) 0xFFFF))
        (bit-and (bit-not s) 0xFFFF)))))

(defn- udp-checksum-valid?
  "Verify the stored UDP checksum against the computed one (pure).
  A stored checksum of 0x0000 means 'sender did not compute' (RFC 768);
  that is reported as invalid rather than guessed (issue #18)."
  [b ip-off udp-off]
  (let [stored (u16be b (+ udp-off 6))]
    (and (pos? stored)
         (= stored (compute-udp-checksum b ip-off udp-off)))))

(defn- dissect-udp
  [b off ip-off]
  {:src-port (u16be b off)
   :dst-port (u16be b (+ off 2))
   :length (u16be b (+ off 4))
   :checksum (hex (u16be b (+ off 6)) 4)
   :checksum-valid (udp-checksum-valid? b ip-off off)})

(defn- dissect-l3
  [b off ethertype]
  (case ethertype
    0x0800 (let [ip (dissect-ipv4 b off)
                 l3-end (+ off (:ihl ip))
                 l4 (case (:protocol ip)
                      "TCP" (dissect-tcp b l3-end)
                      "UDP" (dissect-udp b l3-end off)
                      nil)]
             (assoc ip :l4 l4))
    nil))

(defn dissect-frame
  "Dissect one Ethernet frame's bytes into EDN (pure)."
  [b]
  (let [eth (dissect-ethernet b 0)
        l3 (dissect-l3 b 14 (:ethertype eth))]
    (cond-> {:eth eth}
      l3 (assoc :ip (dissoc l3 :l4))
      (:l4 l3) (assoc :l4 (:l4 l3)))))

;; ── pcap file ───────────────────────────────────────────────────────────

(defn dissect-pcap
  "Parse a classic pcap byte array (as from reading a file into bytes)
  and dissect each frame. Returns vector of
  {:frame n :ts-sec n :ts-usec n :ts-unit :us|:ns :eth ... :ip ... :l4 ...}

  :ts-usec is the raw timestamp-fraction field; :ts-unit (:us or :ns, from
  the file magic) says what unit it is in, so nanosecond pcap files are not
  silently misread as microseconds (issue #9)."
  [b]
  (let [{endian :endian, ts-unit :ts-unit} (detect-endianness b)
        rd32 (fn [off] (if (= endian :little)
                         (let [a (u8 b off) bb (u8 b (inc off)) c (u8 b (+ off 2)) d (u8 b (+ off 3))]
                           (+ (* d 16777216) (* c 65536) (* bb 256) a))
                         (+ (* (u8 b off) 16777216) (* (u8 b (inc off)) 65536)
                            (* (u8 b (+ off 2)) 256) (u8 b (+ off 3)))))
        linktype (rd32 20)
        _ (when (not= linktype 1)  ; Ethernet only for now
            (throw (ex-info "unsupported linktype" {:kind ::linktype :linktype linktype})))
        frames (volatile! [])
        total (alength b)]
    (loop [off 24]
      (when (< (+ off 16) total)
        (let [ts-sec  (rd32 off)
              ts-frac (rd32 (+ off 4))
              caplen  (rd32 (+ off 8))
              origlen (rd32 (+ off 12))
              data-off (+ off 16)
              ;; caplen must fit inside the file: trusting a lying header
              ;; reads out of bounds (phantom fields) or allocates a
              ;; (range caplen)-sized array from garbage (issue #30)
              available (- total data-off)]
          (when (> caplen available)
            (throw (ex-info "truncated pcap record: caplen exceeds remaining bytes"
                            {:kind ::truncated-record
                             :caplen caplen
                             :available available})))
          (vswap! frames conj
                  (merge {:frame (inc (count @frames))
                          :ts-sec ts-sec
                          :ts-usec ts-frac
                          :ts-unit ts-unit
                          :caplen caplen
                          :origlen origlen}
                         (dissect-frame (into-array (map #(aget b (+ data-off %)) (range caplen))))))
          (recur (+ data-off caplen)))))
    @frames))
