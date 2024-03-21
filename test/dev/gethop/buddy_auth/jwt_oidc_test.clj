;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/

(ns dev.gethop.buddy-auth.jwt-oidc-test
  (:require [amazonica.aws.cognitoidp :as idp]
            [amazonica.core]
            [buddy.core.codecs :as codecs]
            [buddy.core.keys :as keys]
            [buddy.core.nonce :as nonce]
            [buddy.sign.jwt :as jwt]
            [clojure.core.cache :as cache]
            [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.spec.alpha :as s]
            [clojure.spec.test.alpha :as stest]
            [clojure.test :refer :all]
            [dev.gethop.buddy-auth.jwt-oidc :as jwt-oidc]
            [dev.gethop.buddy-auth.jwt-oidc.impl.core :as impl])
  (:import [clojure.lang ExceptionInfo]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Fixtures
(defn- enable-instrumentation
  [f]
  (-> (stest/enumerate-namespace 'dev.gethop.buddy-auth.jwt-oidc) stest/instrument)
  (-> (stest/enumerate-namespace 'dev.gethop.buddy-auth.jwt-oidc.impl.core) stest/instrument)
  (f))

(use-fixtures :once enable-instrumentation)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Cryptographic keys, in various formats

(def rsa-priv-key
  "RSA private key used for unit tests, in PEM format"
  (keys/private-key (io/resource "_files/privkey.rsa.pem")))

(def rsa-pub-key
  "RSA public key used for unit tests, in PEM format"
  (keys/public-key (io/resource "_files/pubkey.rsa.pem")))

(def jwk-rsa-kid
  "kid for RSA keys in JWK format"
  "rsa")

(def jwk-rsa
  "RSA public key used for unit tests, in JWK format"
  (->
   (keys/public-key->jwk rsa-pub-key)
   (assoc :kid jwk-rsa-kid :alg "RS256" :use "sig")))

(def ecdsa-priv-key
  "ECDSA private key used for unit tests, in PEM format"
  (keys/private-key (io/resource "_files/privkey.ecdsa.pem")))

(def ecdsa-pub-key
  "ECDSA public key used for unit tests, in PEM format"
  (keys/public-key (io/resource "_files/pubkey.ecdsa.pem")))

(def jwk-ecdsa-kid
  "kid for ECDSA keys in JWK format"
  "ecdsa")

(def jwk-ecdsa
  "ECDSA public key used for unit tests, in JWK format"
  (->
   (keys/public-key->jwk ecdsa-pub-key)
   (assoc :kid jwk-ecdsa-kid :alg "ES256" :use "sig")))

(def hs256-key
  "HMAC-SHA256 secret key used for unit tests"
  (nonce/random-bytes 64))

(def jwk-hs256-kid
  "kid for HMAC-SHA256 keys in JWK format"
  "hs256")

(def jwk-hs256
  "HS256 secret key used for unit tests, in JWK format"
  ;; See https://tools.ietf.org/html/rfc7518#section-6.4 for details
  (->
   {:kty "oct" :k (codecs/bytes->b64-str hs256-key)}
   (assoc :kid jwk-hs256-kid :alg "HS256" :use "sig")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; OpenID Issuer(s) related configuration

(def server-port
  "Port of the server used for unit tests"
  8888)

(def issuer-url
  "OIDC issuer URL used for unit tests."
  (format "http://localhost:%s/magnet/buddy-auth/jwt-oidc" server-port))

(def audience
  "OIDC audience used for unit tests."
  "ac7af362-9f71-442a-baaa-9be2813a3ff5")

(def jwks-uri
  "OIDC JWKS URL used for unit tests."
  (str issuer-url "/.well-known/jwks.json"))

(def well-known-url
  "OIDC \".well-know\" configuration URL used for unit tests."
  (str issuer-url "/.well-known"))

(def default-token-ttl
  "In seconds"
  (* 60 60))

(def sub
  "Subject Identifier for the ID Tokens"
  "7f1370ed-db92-4e32-94cc-036d3985dbe2")

(def thirty-mins
  "Thirty minutes, in seconds"
  (* 30 60))

(def one-day
  "One day, in seconds"
  (* 24 60 60))

(def max-cached-tokens
  "Maximum number of validated tokens to cache"
  3)

(def connection-policy
  "Default connection policy for tests, for JWKS retrieval"
  {:timeout 500
   :retries 3})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Auxiliary functions & macros

(defn now-in-secs
  "Returns current System time, expressed in seconds.
  Truncates to the lower integer second."
  []
  (quot (System/currentTimeMillis) 1000))

(s/def ::required-token-claims
  (s/keys :req-un [::sub
                   ::iss
                   ::aud
                   ::exp]))

(defn create-token
  "Create an OIDC ID token with the given `claims`.

  Use `sign-key` to sign the ID token claims, with `kid` key type, and
  `alg` signing algorithm. `claims` must have, at least, the claims
  defined in the :required-token-claims spec."
  [claims {:keys [sign-key kid alg] :as _sign-opts}]
  {:pre [(s/valid? ::required-token-claims claims)]}
  (let [iat (now-in-secs)]
    (jwt/sign (assoc claims :iat iat)
              sign-key
              {:header {:kid kid} :alg alg})))

(defn get-cognito-token
  "Get an OpenID Connect ID token from AWS Cognito.

  If either `username` or `password` is wrong, returns `nil`.
  If case of any other error, also returns `nil``."
  [username password]
  (try
    (let [client_id (System/getenv "COGNITO_TESTS_USER_POOL_CLIENT_ID")
          resp (idp/initiate-auth {:with-auth-flow "USER_PASSWORD_AUTH"
                                   :with-auth-parameters {"USERNAME" username
                                                          "PASSWORD" password}
                                   :with-client-id client_id})]
      (get-in resp [:authentication-result :id-token]))
    (catch com.amazonaws.AmazonServiceException _
      nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Actual tests

(deftest test-get-jwks-from-jwks-uri
  (testing "Only return non-symmetric keys"
    (let [asymmetric-keys {jwk-rsa-kid rsa-pub-key
                           jwk-ecdsa-kid  ecdsa-pub-key}
          jwk-keys [jwk-rsa jwk-ecdsa jwk-hs256]
          context {:pubkey-cache (impl/create-pubkey-cache jwt-oidc/one-day)
                   :token-cache (impl/create-token-cache 10)
                   :claims  {:iss issuer-url
                             :aud audience}
                   :logger nil
                   :connection-policy connection-policy
                   :jwks-uri jwks-uri}]
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (is (= asymmetric-keys (impl/get-jwks-from-jwks-uri context jwks-uri)))))))

(deftest test-get-jwks-from-well-known
  (testing "Only return non-symmetric keys"
    (let [asymmetric-keys {jwk-rsa-kid rsa-pub-key
                           jwk-ecdsa-kid  ecdsa-pub-key}
          jwk-keys [jwk-rsa jwk-ecdsa jwk-hs256]
          context {:pubkey-cache (impl/create-pubkey-cache jwt-oidc/one-day)
                   :token-cache (impl/create-token-cache 10)
                   :claims  {:iss issuer-url
                             :aud audience}
                   :logger nil
                   :connection-policy connection-policy
                   :well-known-url well-known-url}]
      (with-redefs [impl/get-url (fn [url _ _]
                                   (condp = url
                                     well-known-url (json/write-str {:jwks_uri jwks-uri})
                                     jwks-uri (json/write-str {:keys jwk-keys})))]
        (is (= asymmetric-keys (impl/get-jwks-from-well-known context well-known-url)))))))

(deftest test-get-jwks
  (let [asymmetric-keys {jwk-rsa-kid rsa-pub-key
                         jwk-ecdsa-kid ecdsa-pub-key}
        jwk-keys [jwk-rsa jwk-ecdsa jwk-hs256]
        context {:pubkey-cache (impl/create-pubkey-cache jwt-oidc/one-day)
                 :token-cache (impl/create-token-cache 10)
                 :claims  {:iss issuer-url
                           :aud audience}
                 :logger nil
                 :connection-policy connection-policy
                 :jwks-uri jwks-uri}]
    (testing "Only return non-symmetric keys"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (is (= asymmetric-keys (impl/get-jwks context)))))
    ;; Remember to reset cache before every testing block!
    (swap! (:pubkey-cache context) empty)
    (testing "Return cached values"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (let [in-cache-before (cache/has? (deref (:pubkey-cache context)) jwks-uri)
              retrieved-1 (impl/get-jwks context)
              in-cache-after (cache/has? (deref (:pubkey-cache context)) jwks-uri)
              retrieved-2 (impl/get-jwks context)
              in-cache-final (cache/has? (deref (:pubkey-cache context)) jwks-uri)]
          (is (and (= asymmetric-keys retrieved-1 retrieved-2)
                   (not in-cache-before)
                   in-cache-after
                   in-cache-final)))))
    (swap! (:pubkey-cache context) empty)
    (testing "Don't cache JKWS we can't retrieve"
      (let [get-url-count (atom 0)
            tries 3]
        (with-redefs [impl/get-url (fn [_ _ _]
                                     (swap! get-url-count inc)
                                     (if (< @get-url-count tries)
                                       nil
                                       (json/write-str {:keys jwk-keys})))]
          (let [retrieved-1 (impl/get-jwks context)
                cached-1 (cache/has? (deref (:pubkey-cache context)) jwks-uri)
                retrieved-2 (impl/get-jwks context)
                cached-2 (cache/has? (deref (:pubkey-cache context)) jwks-uri)
                retrieved-3 (impl/get-jwks context)
                cached-3 (cache/has? (deref (:pubkey-cache context)) jwks-uri)
                retrieved-4 (impl/get-jwks context)
                cached-4 (cache/has? (deref (:pubkey-cache context)) jwks-uri)]
            (is (and (empty? retrieved-1)
                     (not cached-1)
                     (empty? retrieved-2)
                     (not cached-2)
                     retrieved-3
                     cached-3
                     retrieved-4
                     cached-4))
            (is (= tries @get-url-count))))))))

(deftest test-validate-token*
  (let [validate-pubkeys {jwk-rsa-kid rsa-pub-key
                          ;; Simulate that the OIDC IdP also provides a symmetric key
                          ;; (that we should refuse to use in any case)
                          jwk-hs256-kid hs256-key}
        exp (+ (now-in-secs) default-token-ttl)
        default-token-claims {:sub sub
                              :iss issuer-url
                              :aud audience
                              :exp exp}
        default-token-signing-opts {:sign-key rsa-priv-key
                                    :kid jwk-rsa-kid
                                    :alg :rs256}
        claims {:iss issuer-url :aud audience}]
    (testing "Successfully validate a token with some key from the Issuer public keys"
      (let [token (create-token default-token-claims default-token-signing-opts)
            result (impl/validate-token* token validate-pubkeys claims nil)]
        (is (= {:sub sub :exp exp} result))))
    (testing "Fail to validate an expired token"
      (let [exp (- (now-in-secs) 1)
            token (create-token (assoc default-token-claims :exp exp) default-token-signing-opts)
            result (impl/validate-token* token validate-pubkeys claims nil)]
        (is (= nil (:sub result)))))
    (testing "Fail to validate a token signed with another key"
      (let [token (create-token default-token-claims (assoc default-token-signing-opts
                                                            :sign-key ecdsa-priv-key
                                                            :kid jwk-ecdsa-kid
                                                            :alg :es256))
            result (impl/validate-token* token validate-pubkeys claims nil)]
        (is (= nil (:sub result)))))
    (testing "Fail to validate a token from another issuer"
      (let [token (create-token (assoc default-token-claims
                                       :iss "https://example.invalid/") default-token-signing-opts)
            result (impl/validate-token* token validate-pubkeys claims nil)]
        (is (= nil (:sub result)))))
    (testing "Fail to validate a token for another audience"
      (let [token (create-token (assoc default-token-claims
                                       :aud (str "another-" audience)) default-token-signing-opts)
            result (impl/validate-token* token validate-pubkeys claims nil)]
        (is (= nil (:sub result)))))
    (testing "Fail to validate a token signed with a symmetric key"
      (let [validate-pubkeys (assoc validate-pubkeys jwk-hs256-kid hs256-key)
            token (create-token default-token-claims (assoc default-token-signing-opts
                                                            :sign-key hs256-key
                                                            :kid jwk-hs256-kid
                                                            :alg :hs256))
            result (impl/validate-token* token validate-pubkeys claims nil)]
        (is (= nil (:sub result)))))
    (testing "Fail to validate a token, not providing valid params"
      (let [token (create-token default-token-claims default-token-signing-opts)]
        (is (thrown? ExceptionInfo (impl/validate-token* token nil claims nil)))
        (is (thrown? ExceptionInfo (impl/validate-token* token -1 claims nil)))))))

(deftest test-validate-token
  (let [jwk-keys [jwk-rsa jwk-ecdsa jwk-hs256]
        exp (+ (now-in-secs) default-token-ttl)
        default-token-claims {:sub sub
                              :iss issuer-url
                              :aud audience
                              :exp exp}
        default-token-signing-opts {:sign-key rsa-priv-key
                                    :kid jwk-rsa-kid
                                    :alg :rs256}
        pubkey-cache (impl/create-pubkey-cache jwt-oidc/one-day)
        token-cache (impl/create-token-cache max-cached-tokens)
        context {:pubkey-cache pubkey-cache
                 :token-cache token-cache
                 :claims {:iss issuer-url
                          :aud audience}
                 :logger nil
                 :connection-policy connection-policy
                 :jwks-uri jwks-uri}]
    (testing "Successfully validate a token with some key from the Issuer public keys, result is cached"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (let [token (create-token default-token-claims default-token-signing-opts)
              result (impl/validate-token context token)]
          (is (and (= sub result)
                   (cache/has? @token-cache token))))))
    ;; Remember to reset cache before every testing block!
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Fail to validate an expired token, result is cached"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (let [exp (- (now-in-secs) 1)
              token (create-token (assoc default-token-claims :exp exp) default-token-signing-opts)
              result (impl/validate-token context token)]
          (is (and (= nil result)
                   (cache/has? @token-cache token))))))
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Check that valid tokens are not cached after their expiry time"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (let [now (now-in-secs)
              token-1-ttl 4
              token-2-ttl 8
              token-1-exp (+ now token-1-ttl)
              token-2-exp (+ now token-2-ttl)
              token-1 (create-token (assoc default-token-claims :exp token-1-exp) default-token-signing-opts)
              token-2 (create-token (assoc default-token-claims :exp token-2-exp) default-token-signing-opts)

              ;; Initial validation
              cached-before-initial-1 (cache/has? @token-cache token-1)
              cached-before-initial-2 (cache/has? @token-cache token-2)
              result-initial-1 (impl/validate-token context token-1)
              result-initial-2 (impl/validate-token context token-2)
              cached-after-initial-1 (cache/has? @token-cache token-1)
              cached-after-initial-2 (cache/has? @token-cache token-2)

              ;; After wating 2000 ms (less than token-1 and token-2 expiration)
              _ (Thread/sleep 2000)
              cached-before-2000-1 (cache/has? @token-cache token-1)
              cached-before-2000-2 (cache/has? @token-cache token-2)
              result-after-2000-1 (impl/validate-token context token-1)
              result-after-2000-2 (impl/validate-token context token-2)
              cached-after-2000-1 (cache/has? @token-cache token-1)
              cached-after-2000-2 (cache/has? @token-cache token-2)

              ;; After wating 6000 ms (longer token-1 expiration, but shorter than token-2)
              _ (Thread/sleep 4000)
              cached-before-6000-1 (cache/has? @token-cache token-1)
              cached-before-6000-2 (cache/has? @token-cache token-2)
              result-after-6000-1 (impl/validate-token context token-1)
              result-after-6000-2 (impl/validate-token context token-2)
              cached-after-6000-1 (cache/has? @token-cache token-1)
              cached-after-6000-2 (cache/has? @token-cache token-2)

              ;; After wating 10000 ms (longer than token-1 and token-2 expiration)
              _ (Thread/sleep 6000)
              cached-before-10000-1 (cache/has? @token-cache token-1)
              cached-before-10000-2 (cache/has? @token-cache token-2)
              result-after-10000-1 (impl/validate-token context token-1)
              result-after-10000-2 (impl/validate-token context token-2)
              cached-after-10000-1 (cache/has? @token-cache token-1)
              cached-after-10000-2 (cache/has? @token-cache token-2)]
          ;; Initial validation
          (is (and (not cached-before-initial-1)
                   (not cached-before-initial-2)
                   cached-after-initial-1
                   cached-after-initial-2
                   (= sub result-initial-1)
                   (= sub result-initial-2)))

          ;; After wating 2000 ms (less than token-1 and token-2 expiration) Both tokens
          ;; should be in cache, and have their original `sub` value.
          (is (and cached-before-2000-1
                   cached-before-2000-2
                   cached-after-2000-1
                   cached-after-2000-2
                   (= sub result-after-2000-1)
                   (= sub result-after-2000-2)))

          ;; After wating 6000 ms (longer token-1 expiration, but shorter than token-2)
          ;; token-1 should have expired before performing the validation and shouldn't be
          ;; in the cache. But should be cached after the call to `validate-token`, as we
          ;; try to revalidate the token and cache the negative result.
          (is (and (not cached-before-6000-1)
                   cached-before-6000-2
                   cached-after-6000-1
                   cached-after-6000-2
                   (= nil result-after-6000-1)
                   (= sub result-after-6000-2)))

          ;; After wating 10000 ms (longer than token-1 and token-2 expiration).
          ;; Before performing the validation, token-1 should be in the cache (from the
          ;; previous negative validation), but token-2 should have expired. But both
          ;; should be in the cache after the validation, as we cache negative validation
          ;; results for token-2.
          (is (and  cached-before-10000-1
                    (not cached-before-10000-2)
                    cached-after-10000-1
                    cached-after-10000-2
                    (= nil result-after-10000-1)
                    (= nil result-after-10000-2))))))
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Check that we don't keep more than configured tokens in validation cache"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (let [token-ttls (mapv #(* 2 %) (range (inc max-cached-tokens) 0 -1))
              now (now-in-secs)
              token-exps (mapv #(+ now %) token-ttls)
              tokens (mapv #(create-token (assoc default-token-claims :exp %) default-token-signing-opts) token-exps)

              ;; Initial validation
              count-before-initial (count @token-cache)
              _ (mapv #(impl/validate-token context %) tokens)
              tokens-initial (mapv #(get-in @token-cache [% :sub]) tokens)
              count-after-initial (count @token-cache)

              ;; After wating 2500 ms
              _ (Thread/sleep 2500)
              count-before-2500 (count @token-cache)
              _ (mapv #(impl/validate-token context %) tokens)
              tokens-2500 (mapv #(get-in @token-cache [% :sub]) tokens)
              count-after-2500 (count @token-cache)

              ;; After wating 5000 ms
              _ (Thread/sleep 2000)
              count-before-5000 (count @token-cache)
              _ (mapv #(impl/validate-token context %) tokens)
              tokens-5000 (mapv #(get-in @token-cache [% :sub]) tokens)
              count-after-5000 (count @token-cache)]
          ;; Initial validation. No token should have expired, and the token with the
          ;; largest TTL should have been expunged from the cache by the other tokens. And
          ;; the cache should be empty before the validations and full (max-cached-tokens)
          ;; after (from current validation).
          (is (= 0 count-before-initial))
          (is (= max-cached-tokens count-after-initial))
          (is (= [nil sub sub sub] tokens-initial))

          ;; After wating 2500 ms the token with the shortest TTL should have expired, and
          ;; the token with the largest TTL should have been expunged from the cache by
          ;; the other tokens (including the expired one). And the cache should be full
          ;; (max-cached-tokens) both before (from the initial validation at the start)
          ;; and after (from current validation).
          (is (= max-cached-tokens count-before-2500))
          (is (= max-cached-tokens count-after-2500))
          (is (= [nil sub sub nil] tokens-2500))

          ;; After wating 5000 ms all tokens except the two with the longest TTLs should
          ;; have expired, and the token with the largest TTL should have been expunged
          ;; from the cache by the other tokens (the expired ones). And the cache should
          ;; be full (max-cached-tokens) both before (from the initial validation at the
          ;; start) and after (from current validation).
          (is (= max-cached-tokens count-before-5000))
          (is (= max-cached-tokens count-after-5000))
          (is (= [nil sub nil nil] tokens-5000)))))
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Fail to validate token, no signing keys available, result is not cached"
      (let [get-url-count (atom 0)
            tries 3]
        (with-redefs [impl/get-url (fn [_ _ _]
                                     (swap! get-url-count inc)
                                     (if (< @get-url-count tries)
                                       nil
                                       (json/write-str {:keys jwk-keys})))]
          (let [token (create-token default-token-claims default-token-signing-opts)
                result-1 (impl/validate-token context token)
                cached-1 (cache/has? @token-cache token)
                result-2 (impl/validate-token context token)
                cached-2 (cache/has? @token-cache token)
                result-3 (impl/validate-token context token)
                cached-3 (cache/has? @token-cache token)
                result-4 (impl/validate-token context token)
                cached-4 (cache/has? @token-cache token)]
            (is (and (nil? result-1)
                     (not cached-1)
                     (nil? result-2)
                     (not cached-2)
                     result-3
                     cached-3
                     result-4
                     cached-4))
            (is (= tries @get-url-count))))))
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Fail to validate a token signed with another key, result is cached"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (let [token (create-token default-token-claims (assoc default-token-signing-opts
                                                              :sign-key hs256-key
                                                              :kid jwk-hs256-kid
                                                              :alg :hs256))
              result (impl/validate-token context token)]
          (is (and (= nil result)
                   (cache/has? @token-cache token))))))
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Fail to validate a token from another issuer, result is cached"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (let [token (create-token (assoc default-token-claims
                                         :iss "https://example.invalid/") default-token-signing-opts)
              result (impl/validate-token context token)]
          (is (and (= nil (:sub result))
                   (cache/has? @token-cache token))))))
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Fail to validate a token for another audience, result is cache"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (let [token (create-token (assoc default-token-claims
                                         :aud (str "another-" audience)) default-token-signing-opts)
              result (impl/validate-token context token)]
          (is (and (= nil (:sub result))
                   (cache/has? @token-cache token))))))
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Fail to validate a token, not providing valid params. Result is not cached"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (let [token (create-token default-token-claims default-token-signing-opts)
              claims-nil (assoc context :claims nil)
              jwks-uri-nil (assoc context :jwks-uri nil)
              iss-nil (assoc-in context [:claims :iss] nil)
              aud-nil (assoc-in context [:claims :aud] nil)]
          (is (thrown? ExceptionInfo (impl/validate-token claims-nil token)))
          (is (not (cache/has? @token-cache token)))
          (is (thrown? ExceptionInfo (impl/validate-token jwks-uri-nil token)))
          (is (not (cache/has? @token-cache token)))
          (is (thrown? ExceptionInfo (impl/validate-token iss-nil token)))
          (is (not (cache/has? @token-cache token)))
          (is (thrown? ExceptionInfo (impl/validate-token aud-nil token)))
          (is (not (cache/has? @token-cache token))))))))

(deftest test-authfn
  (let [jwk-keys [jwk-rsa jwk-ecdsa jwk-hs256]
        now (now-in-secs)
        exp (+ now default-token-ttl)
        default-token-claims {:sub sub
                              :iss issuer-url
                              :aud audience
                              :exp exp}
        default-token-signing-opts {:sign-key rsa-priv-key
                                    :kid jwk-rsa-kid
                                    :alg :rs256}
        logger nil
        config {:claims {:iss issuer-url
                         :aud audience}
                :jwks-uri jwks-uri
                :logger logger}
        token (create-token default-token-claims default-token-signing-opts)]
    (testing "authfn returns a function"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (is (fn? (jwt-oidc/authfn config)))))
    (testing "Success authentication with valid token"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (let [authfn (jwt-oidc/authfn config)]
          (is (= sub (authfn {} token))))))
    (testing "With existig but not expired yet token"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (let [authfn (jwt-oidc/authfn (assoc-in config [:claims :now]
                                                (+ (now-in-secs) thirty-mins)))]
          (is (= sub (authfn {} token))))))
    (testing "With expired token"
      (with-redefs [impl/get-url (fn [_ _ _]
                                   (json/write-str {:keys jwk-keys}))]
        (let [authfn (jwt-oidc/authfn (assoc-in config [:claims :now]
                                                (+ (now-in-secs) one-day)))]
          (is (= nil (authfn {} token))))))
    (testing "With invalid aud claim"
      (is (thrown? ExceptionInfo
                   (jwt-oidc/authfn (assoc-in config [:claims :aud] nil))))
      (is (thrown? ExceptionInfo
                   (jwt-oidc/authfn (assoc-in config [:claims :aud] []))))
      (is (thrown? ExceptionInfo
                   (jwt-oidc/authfn (assoc-in config [:claims :aud] [nil]))))
      (is (thrown? ExceptionInfo
                   (jwt-oidc/authfn (assoc-in config [:claims :aud] ["some-aud" nil]))))
      (is (thrown? ExceptionInfo
                   (jwt-oidc/authfn (assoc-in config [:claims :aud] [nil "some-aud"])))))))

(def ^:private cognito-user-credentials
  {:username (System/getenv "COGNITO_TESTS_USERNAME")
   :password (System/getenv "COGNITO_TESTS_PASSWORD")
   :subject (System/getenv "COGNITO_TESTS_SUB")})

(def ^:private cognito-config
  {:claims {:iss (System/getenv "COGNITO_TESTS_ISSUER_URL")
            :aud (System/getenv "COGNITO_TESTS_AUDIENCE")}
   :jwks-uri (System/getenv "COGNITO_TESTS_JWKS_URI")
   :logger nil})

(deftest ^:integration test-cognito-token-validation
  (let [{:keys [username password subject]} cognito-user-credentials
        token (get-cognito-token username password)
        authfn (jwt-oidc/authfn cognito-config)]
    (testing "New valid token"
      (is (= subject (authfn {} token))))
    (testing "With existig but not expired yet token"
      (let [authfn (jwt-oidc/authfn (assoc-in
                                     cognito-config [:claims :now]
                                     (+ (now-in-secs) thirty-mins)))]
        (is (= subject (authfn {} token)))))
    (testing "With expired token"
      (let [authfn (jwt-oidc/authfn (assoc-in cognito-config [:claims :now]
                                              (+ (now-in-secs) one-day)))]
        (is (= nil (authfn {} token)))))))
