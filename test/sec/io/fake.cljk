(ns sec.io.fake
  "Fake IOProvider for tests. Deterministic, no real sockets.
  Configured with a map of host:port -> response string, and an optional
  set of refused ports. Records every send-bytes call so tests can assert
  the exact wire bytes through the seam (see RequestLog)."
  (:require [sec.io :as io]))

(defprotocol RequestLog
  "Test-side read-back seam: what the fake provider was asked to send.
  Implemented by fake-provider. The log survives close-conn, so tests can
  inspect traffic after a full send/connect run has closed its conns."
  (recorded-requests [this]
    "Vector of {:conn-id, :bytes} in send order (empty if nothing was sent)."))

(defn fake-provider
  "opts: {:responses {\"host:port\" \"raw response...\"}
         :refused #{8080 ...}   ; ports that answer refused
         :silent #{}            ; ports that hang (no conn-id, no refused flag)
         :unknown #{}}          ; ports returning an unrecognized result shape
                                ; (e.g. {:error msg}) — exercises :unknown path"
  [{:keys [responses refused silent unknown]
    :or {responses {} refused #{} silent #{} unknown #{}}}]
  (let [id (atom 0)
        open-conns (atom {})
        req-log (atom [])]
    (reify
      io/IOProvider
      (open-conn [_ host port]
        (cond
          (contains? silent port) {}
          (contains? refused port) {:refused true}
          (contains? unknown port) {:error "simulated provider confusion"}
          :else (let [cid (swap! id inc)]
                  (swap! open-conns assoc cid {:host host :port port})
                  {:conn-id cid})))
      (send-bytes [_ conn-id bytes]
        (swap! open-conns assoc-in [conn-id :request] bytes)
        (swap! req-log conj {:conn-id conn-id :bytes bytes})
        {:bytes-sent (count bytes)})
      (recv-bytes [_ conn-id _timeout-ms]
        (let [{:keys [host port]} (get @open-conns conn-id)]
          (if-let [resp (get responses (str host ":" port))]
            {:bytes resp :closed? true}
            {:bytes "" :closed? true})))
      (close-conn [_ conn-id]
        (swap! open-conns dissoc conn-id)
        {})
      RequestLog
      (recorded-requests [_] @req-log))))
