(ns sec.http
  "HTTP request/response analysis + replay composition — the burpsuite
  equivalent slice. Pure `.cljc`: parse, mutate, re-serialize. Sending a
  composed request goes through a `sec.io` provider (ADR-2609051100)."
  (:require [clojure.string :as str]
            [sec.io :as io]))

;; ── request parsing ─────────────────────────────────────────────────────

(defn parse-request
  "Parse a raw HTTP request string into EDN:
  {:method :path :version :headers {lowercased -> value} :body}
  Headers with the same name repeat into a vector value."
  [raw]
  (let [[head body] (if-let [i (str/index-of raw "\r\n\r\n")]
                      [(subs raw 0 i) (subs raw (+ i 4))]
                      [raw ""])
        lines (str/split-lines head)
        [method path version] (str/split (first lines) #" " 3)
        headers (reduce
                  (fn [acc line]
                    (if-let [i (str/index-of line ":")]
                      (let [k (str/lower-case (str/trim (subs line 0 i)))
                            v (str/trim (subs line (inc i)))]
                        (update acc k (fn [old] (if old (if (vector? old) (conj old v) [old v]) v))))
                      acc))
                  {}
                  (rest lines))]
    {:method method
     :path path
     :version version
     :headers headers
     :body body}))

(defn parse-response
  "Parse a raw HTTP response string: {:version :status :reason :headers :body}"
  [raw]
  (let [[head body] (if-let [i (str/index-of raw "\r\n\r\n")]
                      [(subs raw 0 i) (subs raw (+ i 4))]
                      [raw ""])
        lines (str/split-lines head)
        [_ status & reason] (str/split (first lines) #" " 3)
        headers (reduce
                  (fn [acc line]
                    (if-let [i (str/index-of line ":")]
                      (let [k (str/lower-case (str/trim (subs line 0 i)))
                            v (str/trim (subs line (inc i)))]
                        (update acc k (fn [old] (if old (if (vector? old) (conj old v) [old v]) v))))
                      acc))
                  {}
                  (rest lines))]
    {:version (first (str/split (first lines) #" " 2))
     :status (some-> status js/parseInt)
     :reason (when reason (str/join " " reason))
     :headers headers
     :body body}))

;; ── mutation ────────────────────────────────────────────────────────────

(defn set-header
  "Set (replace) a header on a parsed request map. Pure."
  [req k v]
  (assoc-in req [:headers (str/lower-case k)] v))

(defn remove-header
  [req k]
  (update req :headers dissoc (str/lower-case k)))

(defn set-body
  "Replace the body and fix Content-Length (or add it if absent)."
  [req body]
  (-> req
      (assoc :body body)
      (set-header "Content-Length" (str (count body)))))

;; ── serialization ───────────────────────────────────────────────────────

(defn render-request
  "Render a parsed (and possibly mutated) request map back to raw wire text."
  [{:keys [method path version headers body]}]
  (let [hdr-lines (mapcat (fn [[k v]]
                            (if (vector? v)
                              (map #(str k ": " %) v)
                              [(str k ": " v)]))
                          headers)]
    (str/join "\r\n"
              (into [(str method " " path " " (or version "HTTP/1.1"))]
                    (conj (vec hdr-lines) "" (or body ""))))))

;; ── replay ──────────────────────────────────────────────────────────────

(defn send-request
  "Send a parsed request through a sec.io provider. Returns parsed response.
  opts: {:provider p :host h :port n (default 80) :timeout-ms n}"
  [{:keys [method path headers body] :as req} opts]
  (let [provider (io/provider! opts)
        host (:host opts)
        port (or (:port opts) 80)
        host-hdr (or (get headers "host") host)
        wire (render-request (assoc req :headers (assoc headers "host" host-hdr)))
        {:keys [conn-id]} (io/open-conn provider host port)]
    (when-not conn-id (throw (ex-info "connect failed" {:host host :port port})))
    (try
      (io/send-bytes provider conn-id wire)
      (loop [acc "" tries 0]
        (let [r (io/recv-bytes provider conn-id (or (:timeout-ms opts) 5000))
              acc (str acc (:bytes r))]
          (cond
            (:timeout r) (parse-response acc)
            (:closed? r) (parse-response acc)
            (< tries 100) (recur acc (inc tries))
            :else (parse-response acc))))
      (finally (io/close-conn provider conn-id)))))

(comment
  ;; analysis session shape (pure parts need no provider):
  (-> "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"
      parse-request
      (set-body "goodbye")
      render-request))
