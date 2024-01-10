;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/

(ns dev.gethop.buddy-auth.jwt-oidc.impl.core
  (:require [buddy.core.keys :as keys]
            [buddy.sign.jws :as jws]
            [buddy.sign.jwt :as jwt]
            [clojure.core.cache :as cache]
            [clojure.core.cache.wrapped :as cw]
            [clojure.data.json :as json]
            [clojure.spec.alpha :as s]
            [coop.magnet.ttlcache :as ttlcache]
            [dev.gethop.buddy-auth.jwt-oidc.impl.specs :as specs]
            [diehard.core :as dh]
            [duct.logger :refer [log]]
            [org.httpkit.client :as http]))

(def ^:const failed-validation-ttl
  "TTL for failed token validations, expressed in milli-seconds"
  (* 1000 60 60))

(def ^:const initial-delay
  "Initial delay for retries, specified in milliseconds."
  250)

(def ^:const max-delay
  "Maximun delay for a connection retry, specified in milliseconds. We
  are using truncated binary exponential backoff, with `max-delay` as
  the ceiling for the retry delay."
  1000)

(def ^:const backoff-ms
  "Retry policy back-off configuration (specified in milliseconds"
  [initial-delay max-delay 2.0])

(def ^:const symmetric-key-types
  "See https://tools.ietf.org/html/rfc7518#section-6.4 for details"
  #{"oct"})

(def symmetric-signature-algs
  "See https://tools.ietf.org/html/rfc7518#section-3.1 and
  https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
  for details. `jws/decode-header` returns the standard algorithm
  names as lower-case keywords, so specify them here as such."
  #{:none :hs256 :hs384 :hs512})

(s/def ::create-pubkey-cache-args (s/cat :pubkeys-expire-in int?))
(s/def ::create-pubkey-cache-ret ::specs/pubkey-cache)
(s/fdef create-pubkey-cache
  :args ::create-pubkey-cache-args
  :ret  ::create-pubkey-cache-ret)

(defn create-pubkey-cache
  "Create a cache for JWK public keys.
  `pubkeys-expire-in` is the TTL for the entries of the cache,
  expressed in seconds"
  [pubkeys-expire-in]
  ;; We expect to hold very few entries in this cache (most of the
  ;; time just one or two). So directly use a TTL cache type (even if
  ;; it doesn't have a limit on the number of entries).
  ;; The caching library expects TTLs in milli-seconds.
  (atom (cache/ttl-cache-factory {} :ttl (* 1000 pubkeys-expire-in))))

(s/def ::create-token-cache-args (s/cat :max-cached-tokens int?))
(s/def ::create-token-cache-ret ::specs/token-cache)
(s/fdef create-token-cache
  :args ::create-token-cache-args
  :ret  ::create-token-cache-ret)

(defn create-token-cache
  "Create a cache for validated tokens.
  The cache is limited in size to `max-cached-tokens`, and uses a LRU
  eviction strategy when the limit is reached. Individually, each
  token is evicted when its time to live (TTL), expressed in
  milli-seconds, is reached."
  [max-cached-tokens]
  (atom
   (-> {}
       (ttlcache/per-item-ttl-cache-factory :ttl-getter (fn [_ v] (:ttl v)))
       (cache/lru-cache-factory :threshold max-cached-tokens))))

(defn- fallback [e logger url]
  (let [details (condp instance? e
                  ;; Socket layer related exceptions
                  java.net.UnknownHostException
                  {:severity :error, :reason :unknown-host}
                  java.net.ConnectException
                  {:severity :warn, :reason :connection-refused}

                  ;; HTTP layer related exceptions
                  org.httpkit.client.TimeoutException
                  {:severity :warn, :reason :timeout}
                  org.httpkit.client.AbortException
                  {:severity :warn, :reason :transfer-aborted}

                  ;; Any other kind of exception
                  java.lang.Throwable
                  {:severity :info, :reason :unknown-reason})]
    (log logger (:severity details) ::cant-get-url {:url url :details (:reason details)})
    nil))

(defn- retry-policy [retries backoff-ms]
  (dh/retry-policy-from-config
   {:max-retries retries
    :backoff-ms backoff-ms
    :retry-on [org.httpkit.client.TimeoutException
               org.httpkit.client.AbortException]}))

(s/def ::get-url-args (s/cat :url ::specs/url :logger ::specs/logger
                             :connection-policy ::specs/connection-policy))
(s/def ::get-url-ret (s/nilable string?))
(s/fdef get-url
  :args ::get-url-args
  :ret  ::get-url-ret)

(defn get-url
  "Retrieve given `url`.
  Uses timeout and retries configuration as specified in
  `connection-policy` for the connection and follows redirects. Logs to
  `logger` any relevant issues that may prevent the url from being
  retrieved.

  Returns `nil` if the connection cannot be stablished, the
  content cannot be retrieved or the status response is not 2xx."
  [url logger {:keys [timeout retries] :as connection-policy}]
  {:pre [(and (s/valid? ::specs/url url)
              (s/valid? ::specs/logger logger)
              (s/valid? ::specs/connection-policy connection-policy))]}
  (dh/with-retry {:policy (retry-policy retries backoff-ms)
                  :retry-on Throwable
                  :fallback (fn [_ e] (fallback e logger url))}
    (let [{:keys [status body error]} @(http/get url {:timeout timeout :as :text})]
      (when error
        (throw error))
      (if (<= 200 status 299)
        body
        (do
          (log logger :info ::get-url-invalid-status {:url url :details {:status status}})
          nil)))))

(s/def ::get-jwks-from-jwks-uri-args (s/cat :context ::specs/context :jwks-uri ::specs/url))
(s/def ::get-jwks-from-jwks-uri-ret (s/nilable ::specs/pubkeys))
(s/fdef get-jwks-from-jwks-uri
  :args ::get-jwks-from-jwks-uri-args
  :ret  ::get-jwks-from-jwks-uri-ret)

(defn get-jwks-from-jwks-uri
  "Get the public keys from the JSON Web Key Set at `jwks-uri`.
  Uses timeout and retries configuration as specified in
  `connection-policy` for the connection.

  Returns a collection with the public keys extracted from the JWKS,
  or `nil` if it can't retrieve them. Logs to `logger` any relevant
  issues that may prevent the key set from being retrieved."
  [{:keys [logger connection-policy] :as _context} jwks-uri]
  {:pre [(and (s/valid? ::specs/url jwks-uri)
              (s/valid? ::specs/logger logger)
              (s/valid? ::specs/connection-policy connection-policy))]}
  (when-let [jwks (get-url jwks-uri logger connection-policy)]
    (try
      (let [ks (:keys (json/read-str jwks
                                     :eof-error? false
                                     :key-fn clojure.core/keyword))
            ;; We don't support symmetric key signatures (see ADR-001),
            ;; so filter those key types out.
            keep-asym-jwk (filter (fn [k] (not (contains? symmetric-key-types (:kty k)))))
            jwks-asym-ks (map (fn [k] {(:kid k) (keys/jwk->public-key k)}))
            get-asym-ks (comp keep-asym-jwk jwks-asym-ks)
            asymmetric-keys (into {} get-asym-ks ks)]
        (log logger :info ::downloaded-asymmetric-keys-successfully {:jwks-uri jwks-uri
                                                                     :asymmetric-keys asymmetric-keys})
        asymmetric-keys)
      (catch Throwable e
        (log logger :error ::invalid-jwks-keys-from-uri {:jwks-uri jwks-uri
                                                         :exception-message (.getMessage e)})
        nil))))

(s/def ::get-jwks-from-well-known-args (s/cat :context ::specs/context :well-known-url ::specs/url))
(s/def ::get-jwks-from-well-known-ret (s/nilable ::specs/pubkeys))
(s/fdef get-jwks-from-well-known
  :args ::get-jwks-from-well-known-args
  :ret  ::get-jwks-from-well-known-ret)

(defn get-jwks-from-well-known
  "Get the public keys from the OIDC Provider JWKS, using the \".well-known\" URL.
  Retrieves the configuration from `well-know-url`, from there the
  JWKS URI, and from that URI the actual JWKS. Uses
  `connection-policy` for time-outs and retries, and logs success or
  failure to `logger`.
  Returns a collection with the public keys or `nil` if the JWKS
  content is not available, or doesn't contain valid public keys."
  [{:keys [logger connection-policy] :as context} well-known-url]
  (when-let [well-known-json (get-url well-known-url logger connection-policy)]
    (try
      (let [well-known-config (json/read-str well-known-json
                                             :eof-error? false
                                             :key-fn clojure.core/keyword)]
        (log logger :info ::downloaded-well-known-config-successfully {:well-known-config-url well-known-url})
        (get-jwks-from-jwks-uri context (:jwks_uri well-known-config)))
      (catch Throwable e
        (log logger :error ::invalid-well-known-config {:well-known-config-url well-known-url
                                                        :exception-message (.getMessage e)})
        nil))))

(s/def ::get-jwks-args (s/cat :context ::specs/context))
(s/def ::get-jwks-ret (s/nilable ::specs/pubkeys))
(s/fdef get-jwks
  :args ::get-jwks-args
  :ret  ::get-jwks-ret)

(defn get-jwks
  "Get the public keys from the JWKS.

  The JWKS can be retrieved either from the `well-known-url` OpenID
  Connect Provider configuration, or from a specific `jwks-uri`. Uses
  `pubkey-cache` for caching results. Uses timeout and retries
  configuration as specified in `connection-policy` for the
  connection.

  Returns a collection with the public keys or `nil` if the JWKS
  content is not available, or doesn't contain valid public keys."
  [{:keys [pubkey-cache jwks-uri well-known-url] :as context}]
  {:pre [(s/valid? ::specs/context context)]}
  (let [uri (or well-known-url jwks-uri)
        value-fn (if well-known-url
                   (partial get-jwks-from-well-known context)
                   (partial get-jwks-from-jwks-uri context))]
    (if-let [jwks (cw/lookup-or-miss pubkey-cache uri value-fn)]
      jwks
      ;; We couldn't get the JWKS for the specified URI. Evict the
      ;; entry from the cache, so we try requesting it again
      ;; from "upstream" next time it's needed. Otherwise, the cached
      ;; entry (with a `nil` value) remains in the cache until it
      ;; expires, preventing token validation in the mean time.
      (cw/evict pubkey-cache uri))))

(s/def ::validate-token*-args (s/cat :token string? :pubkeys ::specs/pubkeys
                                     :claims ::specs/claims :logger ::specs/logger))
(s/def ::validate-token*-ret ::specs/token-details)
(s/fdef validate-token*
  :args ::validate-token*-args
  :ret  ::validate-token*-ret)

(defn validate-token*
  "Validate an OpenId Connect ID `token` against the token issuer.
  `pubkeys` is a collection of public keys that can have signed the
  token. The `claims` map should contain at least the following
  keys:

    :iss Case-sensitive URL for the Issuer Identifier.
    :aud Audience(s) the ID Token is intended for.

  A map is returned with the following keys:

    :sub The identity (subject) extracted from the token if valid. Otherwise, `nil`.

    :exp The expiry time (exp) extracted from the token if valid, as a number
         representing the number of seconds from 1970-01-01T00:00:00Z as
         measured in UTC. Otherwise, `nil`."
  [token pubkeys claims logger]
  {:pre [(and (s/valid? string? token)
              (s/valid? ::specs/pubkeys pubkeys)
              (s/valid? ::specs/claims claims)
              (s/valid? ::specs/logger logger))]}
  ;; Verify the tokens, following the OpenId Connect ID token validation instructions
  ;; http://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation
  (try
    (let [token-header (jws/decode-header token)
          token-alg (:alg token-header)
          pubkey (get pubkeys (:kid token-header))]
      (cond
        ;; Only process asymmetric key signatures
        (contains? symmetric-signature-algs token-alg)
        (do
          (log logger :info ::contains-symmetric-signature-algs)
          {:sub nil :exp nil})

        (not pubkey)
        (do
          (log logger :info ::token-uses-invalid-pubkey)
          {:sub nil :exp nil})

        :else
        (let [aud (:aud claims)
              claims (-> claims
                         (dissoc :aud)
                         (assoc :alg token-alg))
              auds (if (coll? aud) aud [aud])
              verified-claims (some (fn [aud]
                                      (try
                                        (jwt/unsign token pubkey (assoc claims :aud aud))
                                        (catch clojure.lang.ExceptionInfo e
                                          (let [{:keys [type cause]} (ex-data e)]
                                            (when-not (and (= type :validation)
                                                           (= cause :aud))
                                              (log logger :error ::unable-to-verify-token)
                                              nil)))
                                        (catch Throwable e
                                          (log logger :error ::exception-verifying-token
                                               {:exception-message (.getMessage e)})
                                          nil)))
                                    auds)]
          (if (empty? verified-claims)
            (do
              (log logger :info ::verified-claims-empty)
              {:sub nil :exp nil})
            (let [{:keys [sub exp]} verified-claims]
              (cond
                (not sub)
                (do
                  (log logger :info ::sub-claim-not-present)
                  {:sub nil :exp nil})

                (not exp)
                (do
                  (log logger :info ::exp-claim-not-present)
                  {:sub nil :exp nil})

                :else
                {:sub sub, :exp exp}))))))
    (catch Throwable e
      ;; If the token is malformed, has been manipulated or doesn't fulfill all the
      ;; validation criteria, buddy functions throw an exception. In that case, we
      ;; consider that the validation has failed.
      (log logger :error ::validate-single-key {:exception-message (.getMessage e)})
      {:sub nil, :exp nil})))

(s/def ::set-ttl-args (s/cat :token ::specs/token-details))
(s/def ::set-ttl-ret (s/and ::specs/token-details ::specs/has-ttl))
(s/fdef set-ttl
  :args ::set-ttl-args
  :ret  ::set-ttl-ret)

(defn- set-ttl
  "Set the TTL cache value (expressed in milli-seconds) for `token`"
  [{:keys [sub exp] :as token}]
  {:pre [(s/valid? ::specs/token-details token)]}
  (if-not sub
    (assoc token :ttl failed-validation-ttl)
    (let [now (System/currentTimeMillis)
          exp-in-millis (* 1000 exp)
          ttl (- exp-in-millis now)]
      (assoc token :ttl ttl))))

(s/def ::validate-token-args (s/cat :context ::specs/context :token string?))
(s/def ::validate-token-ret ::specs/sub)
(s/fdef validate-token
  :args ::validate-token-args
  :ret  ::validate-token-ret)

(defn validate-token
  "Validate OpenID Connect ID `token`, caching results to speed up recurrent validations.
  Returns the `:sub` claim from the token, or `nil` if the token is
  invalid. `context` is a map with at least the following keys:

  :pubkey-cache A `clojure.core.cache` compatible instance, to cache the public keys
              of the Issuer.
  :token-cache A `clojure.core.cache` compatible instance, to cache token validation results.
  :claims A map with the claims that the token must satisfy. At least
          the following keys must exist:
             :iss Case-sensitive URL for the Issuer Identifier.
             :aud Audience(s) the ID Token is intended for.
  :logger A logger compatible with Duct/logger protocol. Any relevant
          issues that may prevent tokens from begin validated are sent to
          this logger.
  :connection-policiy Optional: A policy for timeouts and retries when
          trying to retrieve the JWKS signing keys.
  :jwks-uri Optional: The URL of the config (OpenID Connect Provider)
          JSON Web Key Set document.
  :well-known-url Optional: The URL of the OpenID Connect Provider
          where Discovery document is available at."
  [{:keys [logger] :as context} token]
  {:pre [(and (s/valid? ::specs/context context)
              (s/valid? string? token))]}
  (let [pubkeys (get-jwks context)]
    (if-not (seq pubkeys)
      (log (:logger context) :error ::cannot-get-jwks-from-uri {:jwks-uri (:jwks-uri context)})
      (let [cache-entry (cw/lookup-or-miss (:token-cache context)
                                           token
                                           #(-> (validate-token* % pubkeys (:claims context) logger)
                                                (set-ttl)))]
        (:sub cache-entry)))))
