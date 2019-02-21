;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/

(ns magnet.buddy-auth.jwt-oidc
  "See https://openid.net/specs/openid-connect-core-1_0.html,
  https://openid.net/specs/openid-connect-basic-1_0.html and
  https://openid.net/specs/openid-connect-discovery-1_0.html for
  terminology and details."
  (:require [buddy.core.keys :as keys]
            [buddy.sign.jws :as jws]
            [buddy.sign.jwt :as jwt]
            [clojure.spec.alpha :as s]
            [clojure.core.cache :as cache]
            [clojure.data.json :as json]
            [clojure.java.io :as io]
            [integrant.core :as ig]
            [org.httpkit.client :as http]
            [uk.me.rkd.ttlcache :as ttlcache]))

(def ^:const default-mct
  "Default value for the number of cached tokens"
  50)

(def ^:const timeout
  "Timeout, in milli-seconds, for JWK keys retrieval through HTTP request"
  (* 1000 2))

(def ^:const one-day
  "One day, expressed in seconds"
  (* 24 60 60))

(def ^:const symmetric-key-types
  "See https://tools.ietf.org/html/rfc7518#section-6.4 for details"
  #{"oct"})

(def symmetric-signature-algs
  "See https://tools.ietf.org/html/rfc7518#section-3.1 and
  https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
  for details. `jws/decode-header` returns the standard algorithm
  names as lower-case keywords, so specify them here as such. "
  #{:hs256 :hs384 :hs512})

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
       (ttlcache/per-item-ttl-cache-factory :ttl-getter (fn [k v] (:ttl v)))
       (cache/lru-cache-factory :threshold max-cached-tokens))))

(s/def ::create-token-cache-args (s/cat :max-cached-tokens int?))
(s/def ::token-cache #(s/valid? ::core-cache @%))
(s/def ::create-token-cache-ret ::token-cache)
(s/fdef create-token-cache
  :args ::create-token-cache-args
  :ret  ::create-token-cache-ret)

(def ^:const failed-validation-ttl
  "TTL for failed token validations, expressed in milli-seconds"
  (* 1000 60 60))

(defn get-url
  "Retrieve given `url`. Uses timeout for the connection and follows redirects.
  Returns `nil` if the connection cannot be stablished, the
  content cannot be retrieved or the status response is not 2xx."
  [url]
  {:pre [(s/valid? ::url url)]}
  (let [{:keys [status body error]} @(http/get url {:timeout timeout :as :text})]
    (when (and (not error) (<= 200 status 299))
      body)))

(s/def ::url #(or (string? %) (instance? java.net.URL %)))
(s/def ::get-url-args (s/cat :url ::url))
(s/def ::get-url-ret (s/or :nil nil? :string string?))
(s/fdef get-url
  :args ::get-url-args
  :ret  ::get-url-ret)

(defn get-jwks*
  "Get the public keys from the JSON Web Key Set at `jwks-uri`.
  Returns a collection with the public keys extracted from the JWKS, or
  `nil` if it can't retrieve them."
  [jwks-uri]
  {:pre [(or (string? jwks-uri) (instance? java.net.URL jwks-uri))]}
  (try
    (let [keys (:keys (json/read-str (get-url jwks-uri)
                                     :eof-error? false
                                     :key-fn clojure.core/keyword))
          ;; We don't support symmetric key signatures (see ADR-001),
          ;; so filter those key types out.
          assymetric-keys (filter #(not (contains? symmetric-key-types (:kty %))) keys)]
      (map keys/jwk->public-key assymetric-keys))
    (catch Exception e
      nil)))

(s/def ::get-jwks*-args (s/cat :jwks-uri ::url))
(s/def ::get-jwks*-ret (s/or :nil nil? :pubkeys coll?))
(s/fdef get-jwks*
  :args ::get-jwks*-args
  :ret  ::get-jwks*-ret)

(defn get-jwks
  "Get the public keys from the JWKS at `jwks-uri`, using `pubkey-cache` for caching results.
  Returns a collection with the public keys or `nil` if the JWKS content
  is not available, or doesn't contain valid public keys."
  [pubkey-cache jwks-uri]
  (cache/lookup (swap! pubkey-cache
                       #(if (cache/has? % jwks-uri)
                          (cache/hit % jwks-uri)
                          (if-let [pubkeys (get-jwks* jwks-uri)]
                            (cache/miss % jwks-uri pubkeys)
                            ;; We didn't get the data to include in the cache, so
                            ;; return the original values (minus the evicted ones).
                            (cache/hit % jwks-uri))))
                jwks-uri))

(s/def ::get-jwks-args (s/cat :pubkey-cache ::pubkey-cache :jwks-uri ::url))
(s/def ::get-jwks-ret (s/or :nil nil? :pubkeys coll?))
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
  [token pubkey {:keys [iss aud] :as claims}]
  {:pre [(not-any? nil? [pubkey iss aud])]}
  ;; Verify the tokens, following the OpenId Connect ID token validation instructions
  ;; http://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation
  (try
    (let [token-header (jws/decode-header token)
          token-alg (:alg token-header)]
      (when-not (contains? symmetric-signature-algs token-alg)
        ;; Only process asymmetric key signatures
        (let [verified-claims (jwt/unsign token pubkey (assoc claims :alg token-alg))]
          (select-keys verified-claims [:sub :exp]))))
    (catch Exception e
      ;; If the token is malformed, has been manipulated or doesn't fulfill all the
      ;; validation criteria, buddy functions throw an exception. In that case, we
      ;; consider that the validation has failed.
      nil)))

(s/def ::pubkey (complement nil?))
(s/def ::iss ::url)
(s/def ::aud (s/or :string string? :coll coll?))
(s/def ::claims (s/keys :req-un [::iss ::aud]))
(s/def ::validate-single-key-args (s/cat :token string? :pubkey ::pubkey :claims ::claims))
(s/def ::sub (s/or :nil nil? :sub string?))
(s/def ::exp (s/or :nil nil? :exp number?))
(s/def ::token-details (s/keys :req-un [::sub ::exp]))
(s/def ::validate-single-key-ret (s/or :nil nil? :token-details ::token-details))
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
  [token pubkeys {:keys [iss aud] :as claims}]
  {:pre [(not-any? nil? [iss aud])
         (coll? pubkeys)]}
  (let [validated (some #(validate-single-key token % claims) pubkeys)]
    (or validated
        {:sub nil :exp nil})))

(s/def ::validate-token*-args (s/cat :token string? :pubkeys (s/coll-of ::pubkey) :claims ::claims))
(s/def ::validate-token*-ret ::token-details)
(s/fdef validate-token*
  :args ::validate-token*-args
  :ret  ::validate-token*-ret)

(defn set-ttl
  "Set the TTL cache value (expressed in milli-seconds) for `token`"
  [{:keys [sub exp] :as token}]
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
  Returns the `:sub` claim from the token, or `nil` if the token is invalid.
  `config` is a map with at least the following keys:

  :pubkey-cache A `clojure.core.cache` compatible instance, to cache the public keys
              of the Issuer.
  :token-cache A `clojure.core.cache` compatible instance, to cache token validation results.
  :jwks-uri The URL of the config (OpenID Connect Provider) JSON Web Key Set document.
  :claims A map with the claims that the token must satisfy. At least
         the following keys must exist:
             :iss Case-sensitive URL for the Issuer Identifier.
             :aud Audience(s) the ID Token is intended for."
  [config token]
  (if-let [pubkeys (get-jwks (:pubkey-cache config) (:jwks-uri config))]
    (let [token-cache (swap! (:token-cache config)
                             #(if (cache/has? % token)
                                (cache/hit % token)
                                (cache/miss % token (->
                                                     (validate-token* token pubkeys (:claims config))
                                                     (set-ttl)))))]
      (:sub (cache/lookup token-cache token)))))

(s/def ::jwks-uri ::url)
(s/def ::config (s/keys :req-un [::pubkey-cache ::token-cache ::jwks-uri ::claims]))
(s/def ::validate-token-args (s/cat :config ::config :token string?))
(s/def ::validate-token-ret ::sub)
(s/fdef validate-token
  :args ::validate-token-args
  :ret  ::validate-token-ret)

(defn authfn
  ""
  [{:keys [claims jwks-uri
           pubkeys-expire-in
           max-cached-tokens]
    :or {pubkeys-expire-in one-day
         max-cached-tokens default-mct} :as options}]
  (let [pubkey-cache (create-pubkey-cache pubkeys-expire-in)
        token-cache (create-token-cache max-cached-tokens)
        config {:claims claims
                :jwks-uri jwks-uri
                :pubkey-cache pubkey-cache
                :token-cache token-cache}]
    (fn [req token]
      (validate-token config token))))

(s/def ::pubkeys-expire-in pos-int?)
(s/def ::max-cached-tokens pos-int?)
(s/def ::authfn-options (s/keys :req-un [::claims ::jwks-uri]
                                :opt-un [::pubkeys-expire-in ::max-cached-tokens]))
(s/def ::authfn-args (s/cat :authfn-options ::authfn-options))
(s/fdef authfn
  :args ::authfn-args)

(defmethod ig/init-key :magnet.buddy-auth/jwt-oidc [_ options]
  (authfn options))
