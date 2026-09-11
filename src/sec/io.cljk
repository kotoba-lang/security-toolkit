(ns sec.io
  "I/O seam for security-toolkit. Pure `.cljc`; no ambient authority.

  Scan/pkt/http logic never opens sockets or captures packets directly.
  A provider implements this protocol and is passed via opts. The JVM and
  Node providers in `sec.io.jvm` / `sec.io.node` are reference adapters;
  production logic must stay provider-free (ADR-2609051100).")

(defprotocol IOProvider
  "Transport seam. All methods return plain EDN data or throw ex-info."
  (open-conn [this host port] "returns {:conn-id ...} or throws")
  (send-bytes [this conn-id bytes] "returns {:bytes-sent n}")
  (recv-bytes [this conn-id timeout-ms] "returns {:bytes ... :closed? bool} or {:timeout true}")
  (close-conn [this conn-id] "returns {}"))

(defn provider!
  "Guard: every entry point must receive a provider. Deny-by-default."
  [opts]
  (or (:provider opts)
      (throw (ex-info "no :provider given — toolkit is authority-free by design;
                       inject a sec.io/IOProvider implementation"
                      {:kind ::provider-required}))))
