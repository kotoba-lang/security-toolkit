(ns sec.pkt
  "pcap reading + protocol dissection — the wireshark equivalent slice.

  Pure `.cljc`. Parses pcap file format (classic, little/big endian) and
  dissects Ethernet / IPv4 / TCP / UDP into plain EDN maps.
  Raw capture (live sniffing) is out of scope here — provider seam only;
  this namespace consumes already-captured bytes (ADR-2609051100)."
  (:require [clojure.string :as str]))

;; ── byte helpers ────────────────────────────────────────────────────────
(defn- u8  [b off] (aget b off))
(defn- u16le [b off] (+ (* (aget b off) 256) (aget b (inc off))))
(defn- u16be [b off] (+ (* (aget b off) 256) (aget b (inc off))))
(defn- u32le [b off] (let [a (u8 b off) bb (u8 b (inc off)) c (u8 b (+ off 2)) d (u8 b (+ off 3))]
                       (+ (* d 16777216) (* c 65536) (* bb 256) a)))
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
  (let [m0 (u8 b 0) m1 (u8 b 1)]
    (cond
      (and (= m0 0xd4) (= m1 0xc3)) {:endian :little :ts-unit :us}
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
   :seq (u32le b (+ off 4))
   :ack (u32le b (+ off 8))
   :data-offset (* (int (/ (u8 b (+ off 12)) 16)) 4)
   :flags {:syn (pos? (bit-and (u8 b (+ off 13)) 0x02))
           :ack (pos? (bit-and (u8 b (+ off 13)) 0x10))
           :fin (pos? (bit-and (u8 b (+ off 13)) 0x01))
           :rst (pos? (bit-and (u8 b (+ off 13)) 0x04))}
   :window (u16be b (+ off 14))})

(defn- dissect-udp
  [b off]
  {:src-port (u16be b off)
   :dst-port (u16be b (+ off 2))
   :length (u16be b (+ off 4))
   :checksum (hex (u16be b (+ off 6)) 4)})

(defn- dissect-l3
  [b off ethertype]
  (case ethertype
    0x0800 (let [ip (dissect-ipv4 b off)
                 l3-end (+ off (:ihl ip))
                 l4 (case (:protocol ip)
                      "TCP" (dissect-tcp b l3-end)
                      "UDP" (dissect-udp b l3-end)
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
        rd16 (if (= endian :little) u16le u16be)
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
              data-off (+ off 16)]
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
