(ns sec.io.fake
  "Fake IOProvider for tests. Deterministic, no real sockets.
  Configured with a map of host:port -> response string, and an optional
  set of refused ports."
  (:require [sec.io :as io]))

(defn fake-provider
  "opts: {:responses {\"host:port\" \"raw response...\"}
         :refused #{8080 ...}   ; ports that answer refused
         :silent #{}            ; ports that hang (no conn-id, no refused flag)
         :unknown #{}}          ; ports returning an unrecognized result shape
                                ; (e.g. {:error msg}) — exercises :unknown path"
  [{:keys [responses refused silent unknown]
    :or {responses {} refused #{} silent #{} unknown #{}}}]
  (let [id (atom 0)
        open-conns (atom {})]
    (reify io/IOProvider
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
        {:bytes-sent (count bytes)})
      (recv-bytes [_ conn-id _timeout-ms]
        (let [{:keys [host port request]} (get @open-conns conn-id)]
          (if-let [resp (get responses (str host ":" port))]
            {:bytes resp :closed? true}
            {:bytes "" :closed? true})))
      (close-conn [_ conn-id]
        (swap! open-conns dissoc conn-id)
        {}))))

(defn recorded-requests
  "Fake providers are reify objects; to inspect recorded traffic, pass the
  same config map to fake-provider and capture state via on-result hooks in
  sec.scan instead. Kept for API symmetry."
  [_provider]
  nil)
