;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/

(ns dev.gethop.buddy-auth.jwt-oidc.impl.specs
  (:require [clojure.core.cache]
            [clojure.spec.alpha :as s]
            [duct.logger]))

(s/def ::core-cache #(satisfies? clojure.core.cache/CacheProtocol %))
(s/def ::pubkey-cache #(s/valid? ::core-cache @%))
(s/def ::token-cache #(s/valid? ::core-cache @%))

(s/def ::url #(or (string? %) (instance? java.net.URL %)))
(s/def ::logger #(satisfies? duct.logger/Logger %))
(s/def ::timeout pos-int?)
(s/def ::retries pos-int?)
(s/def ::connection-policy (s/keys :req-un [::timeout ::retries]))

(s/def ::iss ::url)
(s/def ::aud (s/or :string string? :coll coll?))
(s/def ::claims (s/keys :req-un [::iss ::aud]))
(s/def ::jwks-uri ::url)
(s/def ::well-known-url ::url)
(s/def ::connection-policy (s/keys :req-un [::timeout ::retries]))
(s/def ::context (s/keys :req-un [::pubkey-cache ::token-cache ::claims ::logger
                                  ::connection-policy (or ::jwks-uri ::well-known-url)]))

(s/def ::sub (s/nilable string?))
(s/def ::exp (s/nilable number?))
(s/def ::token-details (s/keys :req-un [::sub ::exp]))
(s/def ::pubkeys map?)

(s/def ::ttl pos-int?)
(s/def ::has-ttl (s/keys :req-un [::ttl]))

