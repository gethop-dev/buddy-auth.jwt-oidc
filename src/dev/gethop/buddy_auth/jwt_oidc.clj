;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/

(ns dev.gethop.buddy-auth.jwt-oidc
  "See https://openid.net/specs/openid-connect-core-1_0.html,
  https://openid.net/specs/openid-connect-basic-1_0.html and
  https://openid.net/specs/openid-connect-discovery-1_0.html for
  terminology and details."
  (:require [clojure.spec.alpha :as s]
            [dev.gethop.buddy-auth.jwt-oidc.impl.core :as impl]
            [dev.gethop.buddy-auth.jwt-oidc.impl.specs :as specs]
            [integrant.core :as ig]))

(def ^:const default-jwks-retrieval-timeout
  "Default timeout for JWK keys retrieval through HTTP request, specified in milli-seconds"
  500)

(def ^:const default-jwks-retrieval-retries
  "Default retry attempts for JKW keys retrieval"
  3)

(def ^:const default-mct
  "Default value for the number of cached tokens"
  50)

(def ^:const one-day
  "One day, expressed in seconds"
  (* 24 60 60))

(s/def ::jwks-retrieval-timeout ::specs/timeout)
(s/def ::jwks-retrieval-retries ::specs/retries)
(s/def ::well-known-url-retrieval-timeout ::specs/timeout)
(s/def ::well-known-url-retrieval-retries ::specs/retries)
(s/def ::pubkeys-expire-in pos-int?)
(s/def ::max-cached-tokens pos-int?)
(s/def ::authfn-options (s/and (s/keys :req-un [::specs/claims
                                                (or ::specs/jwks-uri
                                                    ::specs/well-known-url)]
                                       :opt-un [::pubkeys-expire-in
                                                ::max-cached-tokens
                                                ::specs/logger
                                                ::jwks-retrieval-timeout
                                                ::jwks-retrieval-retries
                                                ::well-known-url-retrieval-timeout
                                                ::well-known-url-retrieval-retries])
                               ;; One, and only one, of the two should be set.
                               (fn [authfn-options]
                                 (= 1 (count (select-keys authfn-options [:jwks-uri
                                                                          :well-known-url]))))))

(s/def ::authfn-args (s/cat :options ::authfn-options))
(s/def ::authfn-ret fn?)
(s/fdef authfn
  :args ::authfn-args
  :ret ::authfn-ret)

(defn authfn
  "buddy-auth authentication function"
  [{:keys [claims
           jwks-uri
           well-known-url
           pubkeys-expire-in
           max-cached-tokens
           logger
           jwks-retrieval-timeout
           jwks-retrieval-retries
           well-know-url-retrieval-timeout
           well-know-url-retrieval-retries]
    :or {pubkeys-expire-in one-day
         max-cached-tokens default-mct
         jwks-retrieval-timeout default-jwks-retrieval-timeout
         jwks-retrieval-retries default-jwks-retrieval-retries
         well-know-url-retrieval-timeout default-jwks-retrieval-timeout
         well-know-url-retrieval-retries default-jwks-retrieval-retries}
    :as options}]
  {:pre [(s/valid? ::authfn-options options)]}
  (let [pubkey-cache (impl/create-pubkey-cache pubkeys-expire-in)
        token-cache (impl/create-token-cache max-cached-tokens)
        context (cond-> {:claims claims
                         :pubkey-cache pubkey-cache
                         :token-cache token-cache
                         :logger logger}

                  jwks-uri
                  (assoc :jwks-uri jwks-uri
                         :connection-policy {:timeout jwks-retrieval-timeout
                                             :retries jwks-retrieval-retries})

                  well-known-url
                  (assoc :well-known-url well-known-url
                         :connection-policy {:timeout well-know-url-retrieval-timeout
                                             :retries well-know-url-retrieval-retries}))]
    (fn [_req token]
      (impl/validate-token context token))))

(defmethod ig/init-key :dev.gethop.buddy-auth/jwt-oidc [_ options]
  (authfn options))
