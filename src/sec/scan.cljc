(ns sec.scan
  "Port/host scanner — the nmap equivalent slice.

  Pure `.cljc`. Connect-scan logic is provider-driven via `sec.io`:
  the scan plan, state classification, and results are all pure;
  sockets happen only through the injected provider.

  Supported slices (ADR-2609051100):
  - TCP connect scan (state classification open/closed/filtered)
  - host sweep (which of a subnet's hosts answer on given ports)
  - service fingerprint by probe payload (HTTP banner grab etc.)
  "
  (:require [sec.io :as io]))

;; ── port state classification ───────────────────────────────────────────

(defn classify-connect
  "Classify one connect attempt result into nmap-like state.
  result is {:ok true} | {:refused true} | {:timeout true} | {:unreachable true}"
  [result]
  (cond
    (:ok result)          :open
    (:refused result)     :closed
    (:timeout result)     :filtered
    (:unreachable result) :filtered
    :else                 :unknown))

;; ── scan plan ───────────────────────────────────────────────────────────

(defn plan
  "Expand a scan spec into an ordered work list (pure).
  spec: {:hosts [\"10.0.0.1\" ...] :ports [22 80 443]}"
  [spec]
  (let [hosts (:hosts spec)
        ports (sort (:ports spec))]
    (vec
      (for [h hosts p ports]
        {:host h :port p}))))

(defn- try-connect
  [provider host port]
  (let [r (io/open-conn provider host port)]
    (cond
      (:conn-id r) (do (io/close-conn provider (:conn-id r))
                       {:ok true})
      (:refused r) {:refused true}
      :else        {:timeout true})))

(defn connect-scan
  "Scan the plan, classify each port. Provider is mandatory.
  opts: {:provider p :on-result (fn [{:keys [host port state]}])}"
  [spec opts]
  (let [provider (io/provider! opts)
        on-result (:on-result opts (fn [_]))
        results (mapv (fn [{:keys [host port] :as item}]
                        (let [state (classify-connect (try-connect provider host port))
                              r (assoc item :state state)]
                          (on-result r)
                          r))
                      (plan spec))]
    results))

(defn open-ports
  "Filter helper: keep only :open results."
  [results]
  (filterv #(= :open (:state %)) results))

(defn host-sweep
  "For each host, is it reachable via any of the given ports?
  Returns [{:host h :alive? bool}] — alive iff any port :open."
  [spec opts]
  (let [by-host (group-by :host (connect-scan spec opts))]
    (mapv (fn [[h rs]] {:host h :alive? (some #(= :open (:state %)) rs)})
          (sort-by first by-host))))
