;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/

(ns dev.gethop.buddy-auth.jwt-oidc
  "See https://openid.net/specs/openid-connect-core-1_0.html,
  https://openid.net/specs/openid-connect-basic-1_0.html and
  https://openid.net/specs/openid-connect-discovery-1_0.html for
  terminology and details."
  (:require [buddy.core.keys :as keys]
            [buddy.sign.jws :as jws]
            [buddy.sign.jwt :as jwt]
            [clojure.spec.alpha :as s]
            [clojure.core.cache :as cache]
            [clojure.core.cache.wrapped :as cw]
            [clojure.data.json :as json]
            [diehard.core :as dh]
            [duct.logger :refer [log]]
            [integrant.core :as ig]
            [org.httpkit.client :as http]
            [coop.magnet.ttlcache :as ttlcache]))

(def ^:const default-jwks-retrieval-timeout
  "Default timeout for JWK keys retrieval through HTTP request, specified in milli-seconds"
  500)

(def ^:const default-jwks-retrieval-retries
  "Default retry attempts for JKW keys retrieval"
  3)

(def ^:const initial-delay
  "Initial delay for retries, specified in milliseconds."
  250)

(def ^:const max-delay
  "Maximun delay for a connection retry, specified in milliseconds. We
  are using truncated binary exponential backoff, with `max-delay` as
  the ceiling for the retry delay."
  1000)

(def ^:const backoff-ms
  [initial-delay max-delay 2.0])

(def ^:const default-mct
  "Default value for the number of cached tokens"
  50)

(def ^:const one-day
  "One day, expressed in seconds"
  (* 24 60 60))

(def ^:const failed-validation-ttl
  "TTL for failed token validations, expressed in milli-seconds"
  (* 1000 60 60))

(def ^:const symmetric-key-types
  "See https://tools.ietf.org/html/rfc7518#section-6.4 for details"
  #{"oct"})

(def symmetric-signature-algs
  "See https://tools.ietf.org/html/rfc7518#section-3.1 and
  https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
  for details. `jws/decode-header` returns the standard algorithm
  names as lower-case keywords, so specify them here as such."
  #{:none :hs256 :hs384 :hs512})

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

(s/def ::logger #(satisfies? duct.logger/Logger %))
(s/def ::core-cache #(satisfies? clojure.core.cache/CacheProtocol %))
(s/def ::create-pubkey-cache-args (s/cat :pubkeys-expire-in int?))
(s/def ::pubkey-cache #(s/valid? ::core-cache @%))
(s/def ::create-pubkey-cache-ret ::pubkey-cache)
(s/fdef create-pubkey-cache
  :args ::create-pubkey-cache-args
  :ret  ::create-pubkey-cache-ret)

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

(s/def ::create-token-cache-args (s/cat :max-cached-tokens int?))
(s/def ::token-cache #(s/valid? ::core-cache @%))
(s/def ::create-token-cache-ret ::token-cache)
(s/fdef create-token-cache
  :args ::create-token-cache-args
  :ret  ::create-token-cache-ret)

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
                  java.lang.Exception
                  {:severity :info, :reason :unknown-reason})]
    (log logger (:severity details) ::cant-get-url {:url url :details (:reason details)})
    nil))

(defn- retry-policy [retries backoff-ms]
  (dh/retry-policy-from-config
   {:max-retries retries
    :backoff-ms backoff-ms
    :retry-on [org.httpkit.client.TimeoutException
               org.httpkit.client.AbortException]}))

(defn get-url
  "Retrieve given `url`.
  Uses timeout and retries configuration as specified in
  `connection-policy` for the connection and follows redirects. Logs to
  `logger` any relevant issues that may prevent the url from being
  retrieved. Returns `nil` if the connection cannot be stablished, the
  content cannot be retrieved or the status response is not 2xx."
  [url logger {:keys [timeout retries] :as connection-policy}]
  {:pre [(and (s/valid? ::url url)
              (s/valid? ::logger logger)
              (s/valid? ::connection-policy connection-policy))]}
  (dh/with-retry {:policy (retry-policy retries backoff-ms)
                  :retry-on Exception
                  :fallback (fn [_ e] (fallback e logger url))}
    (let [{:keys [status body error]} @(http/get url {:timeout timeout :as :text})]
      (when error
        (throw error))
      (if (<= 200 status 299)
        body
        (do
          (log logger :info ::get-url-invalid-status {:url url :details {:status status}})
          nil)))))

(s/def ::url #(or (string? %) (instance? java.net.URL %)))
(s/def ::timeout pos-int?)
(s/def ::retries pos-int?)
(s/def ::connection-policy (s/keys :req-un [::timeout
                                            ::retries]))
(s/def ::get-url-args (s/cat :url ::url :logger ::logger :connection-policy ::connection-policy))
(s/def ::get-url-ret (s/nilable string?))
(s/fdef get-url
  :args ::get-url-args
  :ret  ::get-url-ret)

(defn get-jwks*
  "Get the public keys from the JSON Web Key Set at `jwks-uri`.
  Uses timeout and retries configuration as specified in
  `connection-policy` for the connection.
  Returns a collection with the public keys extracted from the JWKS,
  or `nil` if it can't retrieve them. Logs to `logger` any relevant
  issues that may prevent the key set from being retrieved."
  [jwks-uri logger connection-policy]
  {:pre [(and (s/valid? ::url jwks-uri)
              (s/valid? ::logger logger)
              (s/valid? ::connection-policy connection-policy))]}
  (when-let [jwks (get-url jwks-uri logger connection-policy)]
    (try
      (let [ks (:keys (json/read-str jwks
                                     :eof-error? false
                                     :key-fn clojure.core/keyword))
            ;; We don't support symmetric key signatures (see ADR-001),
            ;; so filter those key types out.
            asymmetric-keys (->> ks
                                 (filter #(not (contains? symmetric-key-types (:kty %))))
                                 (map keys/jwk->public-key))]
        (log logger :info ::downloaded-asymmetric-keys-successfully {:jwks-uri jwks-uri
                                                                     :asymmetric-keys asymmetric-keys})
        asymmetric-keys)
      (catch Exception e
        (log logger :error ::invalid-jwks-keys-from-uri {:jwks-uri jwks-uri
                                                         :exception-message (.getMessage e)})
        nil))))

(s/def ::get-jwks*-args (s/cat :jwks-uri ::url :logger ::logger :connection-policy ::connection-policy))
(s/def ::get-jwks*-ret (s/nilable coll?))
(s/fdef get-jwks*
  :args ::get-jwks*-args
  :ret  ::get-jwks*-ret)

(defn get-jwks
  "Get the public keys from the JWKS at `jwks-uri`, using `pubkey-cache` for caching results.
  Uses timeout and retries configuration as specified in
  `connection-policy` for the connection.  Returns a collection with
  the public keys or `nil` if the JWKS content is not available, or
  doesn't contain valid public keys."
  [pubkey-cache jwks-uri logger connection-policy]
  {:pre [(and (s/valid? ::pubkey-cache pubkey-cache)
              (s/valid? ::url jwks-uri)
              (s/valid? ::logger logger)
              (s/valid? ::connection-policy connection-policy))]}
  (cache/lookup (swap! pubkey-cache
                       #(if (cache/has? % jwks-uri)
                          (cache/hit % jwks-uri)
                          (if-let [pubkeys (get-jwks* jwks-uri logger connection-policy)]
                            (cache/miss % jwks-uri pubkeys)
                            ;; We didn't get the data to include in the cache, so
                            ;; return the original values (minus the evicted ones).
                            (do
                              (log logger :info ::using-original-values {:jwks-uri jwks-uri
                                                                         :asymmetric-keys (cache/hit % jwks-uri)})
                              (cache/hit % jwks-uri)))))
                jwks-uri))

(s/def ::get-jwks-args (s/cat :pubkey-cache ::pubkey-cache :jwks-uri ::url :logger ::logger
                              :connection-policy ::connection-policy))
(s/def ::get-jwks-ret (s/nilable coll?))
(s/fdef get-jwks
  :args ::get-jwks-args
  :ret  ::get-jwks-ret)

(defn validate-single-key
  "Validate OpenId Connect ID `token`, using `pubkey`.
  The `claims` map should contain at least the following keys:

    :iss Case-sensitive URL for the Issuer Identifier.
    :aud Audience(s) the ID Token is intended for.

  If the token is valid, a map is returned with the following keys:

    :sub The identity (subject) extracted from the token (if valid).

    :exp The expiry time (exp) extracted from the token (if valid), as a
         number representing the number of seconds from 1970-01-01T00:00:00Z
         as measured in UTC.

    If the token is not valid, it returns `nil`."
  [token pubkey claims logger]
  {:pre [(and (s/valid? string? token)
              (s/valid? ::pubkey pubkey)
              (s/valid? ::claims claims)
              (s/valid? ::logger logger))]}
  ;; Verify the tokens, following the OpenId Connect ID token validation instructions
  ;; http://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation
  (try
    (let [token-header (jws/decode-header token)
          token-alg (:alg token-header)
          aud (:aud claims)
          claims (-> claims
                     (dissoc :aud)
                     (assoc :alg token-alg))]
      ;; Only process asymmetric key signatures
      (if-not (contains? symmetric-signature-algs token-alg)
        ;; aud can be a collection of audiences and we need to check if the token
        ;; contains any of them. Beware that aud can be a simple string too so make
        ;; we always use a collection.
        (let [auds (if (coll? aud) aud [aud])
              verified-claims (some (fn [aud]
                                      (try
                                        (jwt/unsign token pubkey (assoc claims :aud aud))
                                        (catch clojure.lang.ExceptionInfo e
                                          (let [{:keys [type cause]} (ex-data e)]
                                            (when-not (and (= type :validation)
                                                           (= cause :aud))
                                              (log logger :error ::unable-to-verify-token)
                                              nil)))
                                        (catch Exception e
                                          (log logger :error ::exception-verifying-token
                                               {:exception-message (.getMessage e)})
                                          nil)))
                                    auds)]
          (if (seq verified-claims)
            (let [{:keys [sub exp]} verified-claims]
              (cond
                (not sub)
                (do
                  (log logger :info ::sub-claim-not-present)
                  nil)

                (not exp)
                (do
                  (log logger :info ::exp-claim-not-present)
                  nil)

                :else
                {:sub sub, :exp exp}))
            (do
              (log logger :info ::verified-claims-empty)
              nil)))
        (do
          (log logger :info ::contains-symmetric-signature-algs)
          nil)))
    (catch Exception e
      ;; If the token is malformed, has been manipulated or doesn't fulfill all the
      ;; validation criteria, buddy functions throw an exception. In that case, we
      ;; consider that the validation has failed.
      (log logger :error ::validate-single-key {:exception-message (.getMessage e)})
      nil)))

(s/def ::pubkey (complement nil?))
(s/def ::iss ::url)
(s/def ::aud (s/or :string string? :coll coll?))
(s/def ::claims (s/keys :req-un [::iss ::aud]))
(s/def ::validate-single-key-args (s/cat :token string? :pubkey ::pubkey :claims ::claims :logger ::logger))
(s/def ::sub (s/nilable string?))
(s/def ::exp (s/nilable number?))
(s/def ::token-details (s/keys :req-un [::sub ::exp]))
(s/def ::validate-single-key-ret (s/nilable ::token-details))
(s/fdef validate-single-key
  :args ::validate-single-key-args
  :ret  ::validate-single-key-ret)

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
              (s/valid? ::pubkeys pubkeys)
              (s/valid? ::claims claims)
              (s/valid? ::logger logger))]}
  (let [validated (some #(validate-single-key token % claims logger) pubkeys)]
    (or validated
        (do
          (log logger :info ::invalid-token {:token token})
          {:sub nil :exp nil}))))

(s/def ::pubkeys (s/coll-of ::pubkey))
(s/def ::validate-token*-args (s/cat :token string? :pubkeys ::pubkeys :claims ::claims :logger ::logger))
(s/def ::validate-token*-ret ::token-details)
(s/fdef validate-token*
  :args ::validate-token*-args
  :ret  ::validate-token*-ret)

(defn set-ttl
  "Set the TTL cache value (expressed in milli-seconds) for `token`"
  [{:keys [sub exp] :as token}]
  {:pre [(s/valid? ::token-details token)]}
  (if-not sub
    (assoc token :ttl failed-validation-ttl)
    (let [now (System/currentTimeMillis)
          exp-in-millis (* 1000 exp)
          ttl (- exp-in-millis now)]
      (assoc token :ttl ttl))))

(s/def ::set-ttl-args (s/cat :token ::token-details))
(s/def ::ttl pos-int?)
(s/def ::has-ttl (s/keys :req-un [::ttl]))
(s/def ::set-ttl-ret (s/and ::token-details ::has-ttl))
(s/fdef set-ttl
  :args ::set-ttl-args
  :ret  ::set-ttl-ret)

(defn validate-token
  "Validate OpenID Connect ID `token`, caching results to speed up recurrent validations.
  Returns the `:sub` claim from the token, or `nil` if the token is
  invalid. Logs to `logger` any relevant issues that may prevent
  tokens from begin validated. Uses timeout and retries configuration
  as specified in `connection-policy` to retrieve the JWK signing keys.
  `config` is a map with at least the following keys:

  :pubkey-cache A `clojure.core.cache` compatible instance, to cache the public keys
              of the Issuer.
  :token-cache A `clojure.core.cache` compatible instance, to cache token validation results.
  :jwks-uri The URL of the config (OpenID Connect Provider) JSON Web Key Set document.
  :claims A map with the claims that the token must satisfy. At least
         the following keys must exist:
             :iss Case-sensitive URL for the Issuer Identifier.
             :aud Audience(s) the ID Token is intended for."
  [config token logger connection-policy]
  {:pre [(and (s/valid? ::config config)
              (s/valid? string? token)
              (s/valid? ::logger logger)
              (s/valid? ::connection-policy connection-policy))]}
  (if-let [pubkeys (get-jwks (:pubkey-cache config) (:jwks-uri config) logger connection-policy)]
    (let [cache-entry (cw/lookup-or-miss (:token-cache config)
                                         token
                                         #(-> (validate-token* % pubkeys (:claims config) logger)
                                              (set-ttl)))]
      (:sub cache-entry))
    (log logger :error ::cant-get-jwks-from-uri {:jwks-uri (:jwks-uri config)})))

(s/def ::jwks-uri ::url)
(s/def ::config (s/keys :req-un [::pubkey-cache ::token-cache ::jwks-uri ::claims]))
(s/def ::validate-token-args (s/cat :config ::config :token string? :logger ::logger
                                    :connection-policy ::connection-policy))
(s/def ::validate-token-ret ::sub)
(s/fdef validate-token
  :args ::validate-token-args
  :ret  ::validate-token-ret)

(defn authfn
  [{:keys [claims jwks-uri
           pubkeys-expire-in
           max-cached-tokens
           jwks-retrieval-timeout
           jwks-retrieval-retries
           logger]
    :or {pubkeys-expire-in one-day
         max-cached-tokens default-mct
         jwks-retrieval-timeout default-jwks-retrieval-timeout
         jwks-retrieval-retries default-jwks-retrieval-retries}
    :as options}]
  {:pre [(s/valid? ::authfn-options options)]}
  (let [pubkey-cache (create-pubkey-cache pubkeys-expire-in)
        token-cache (create-token-cache max-cached-tokens)
        config {:claims claims
                :jwks-uri jwks-uri
                :pubkey-cache pubkey-cache
                :token-cache token-cache}
        connection-policy {:timeout jwks-retrieval-timeout
                           :retries jwks-retrieval-retries}]
    (fn [_req token]
      (validate-token config token logger connection-policy))))

(s/def ::pubkeys-expire-in pos-int?)
(s/def ::max-cached-tokens pos-int?)
(s/def ::jwks-retrieval-timeout pos-int?)
(s/def ::jwks-retrieval-retries pos-int?)
(s/def ::authfn-options (s/keys :req-un [::claims
                                         ::jwks-uri]
                                :opt-un [::pubkeys-expire-in
                                         ::max-cached-tokens
                                         ::jwks-retrieval-timeout
                                         ::jwks-retrieval-retries
                                         ::logger]))
(s/def ::authfn-args (s/cat :options ::authfn-options))
(s/fdef authfn
  :args ::authfn-args)

(defmethod ig/init-key :dev.gethop.buddy-auth/jwt-oidc [_ options]
  (authfn options))
