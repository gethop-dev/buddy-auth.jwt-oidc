;; This Source Code Form is subject to the terms of the Mozilla Public
;; License, v. 2.0. If a copy of the MPL was not distributed with this
;; file, You can obtain one at http://mozilla.org/MPL/2.0/

(ns magnet.buddy-auth.jwt-oidc-test
  (:require [amazonica.aws.cognitoidp :as idp]
            [amazonica.core :as amazonica]
            [buddy.core.codecs.base64 :as base64]
            [buddy.core.keys :as keys]
            [buddy.core.nonce :as nonce]
            [buddy.sign.jwt :as jwt]
            [clojure.core.cache :as cache]
            [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.spec.test.alpha :as stest]
            [clojure.test :refer :all]
            [magnet.buddy-auth.jwt-oidc :as jwt-oidc])
  (:import [clojure.lang ExceptionInfo]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Fixtures
(defn enable-instrumentation [f]
  (-> (stest/enumerate-namespace 'magnet.buddy-auth.jwt-oidc) stest/instrument)
  (f))

(use-fixtures :once enable-instrumentation)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Cryptographic keys, in various formats

(def rsa-priv-key (keys/private-key (io/resource "_files/privkey.rsa.pem")))

(def rsa-pub-key (keys/public-key (io/resource "_files/pubkey.rsa.pem")))

(def jwk-rsa-kid
  "rsa")

(def jwk-rsa
  (->
   (keys/public-key->jwk rsa-pub-key)
   (assoc :kid jwk-rsa-kid :alg "RS256" :use "sig")))

(def ecdsa-priv-key (keys/private-key (io/resource "_files/privkey.ecdsa.pem")))

(def ecdsa-pub-key (keys/public-key (io/resource "_files/pubkey.ecdsa.pem")))

(def jwk-ecdsa-kid
  "ecdsa")

(def jwk-ecdsa
  (->
   (keys/public-key->jwk ecdsa-pub-key)
   (assoc :kid jwk-ecdsa-kid :alg "ES256" :use "sig")))

(def hs256-key
  (nonce/random-bytes 64))

(def jwk-hs256-kid
  "hs256")

(def jwk-hs256
  ;; See https://tools.ietf.org/html/rfc7518#section-6.4 for details
  (->
   {:kty "oct" :k (apply str (map char (base64/encode hs256-key true)))}
   (assoc :kid jwk-hs256-kid :alg "HS256" :use "sig")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; OpenID Issuer(s) related configuration

(def server-port
  8888)

(def issuer-url
  (format "http://localhost:%s/magnet/buddy-auth/jwt-oidc" server-port))

(def audience
  "ac7af362-9f71-442a-baaa-9be2813a3ff5")

(def jwks-uri
  (str issuer-url "/.well-known/jwks.json"))

(def openid-configuration
  {:issuer issuer-url
   :authorization_endpoint (str issuer-url "/authorize")
   :token_endpoint (str issuer-url "/token")
   :userinfo_endpoint (str issuer-url "/userinfo")
   :jwks_uri jwks-uri
   :registration_endpoint (str issuer-url "/register")
   :scopes_supported ["openid"]
   :response_types_supported ["code" "id_token," "token id_token"]
   :subject_types_supported ["public"]
   :id_token_signing_alg_values_supported ["RS256" "ES256" "HS256"]})

(def provider
  {:issuer issuer-url
   :audience audience
   :jwks-uri jwks-uri})

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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Auxiliary functions & macros

(defn- now-in-secs
  "Returns current System time, expressed in seconds.
  Truncates to the lower integer second."
  []
  (quot (System/currentTimeMillis) 1000))

(defn- create-token
  [{:keys [sub iss aud sign-key kid alg exp]}]
  (let [iat (now-in-secs)
        exp exp]
    (jwt/sign {:sub sub :iss iss :aud aud :iat iat :exp exp}
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
    (catch com.amazonaws.AmazonServiceException e
      nil)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Actual tests

(deftest test-get-jwks*
  (testing "Only return non-symmetric keys"
    (let [asymmetric-keys [rsa-pub-key ecdsa-pub-key]
          jwk-keys [jwk-rsa jwk-ecdsa jwk-hs256]]
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (is (= asymmetric-keys (jwt-oidc/get-jwks* jwks-uri)))))))

(deftest test-get-jwks
  (let [asymmetric-keys [rsa-pub-key ecdsa-pub-key]
        jwk-keys [jwk-rsa jwk-ecdsa jwk-hs256]
        pubkey-cache (jwt-oidc/create-pubkey-cache jwt-oidc/one-day)]
    (testing "Only return non-symmetric keys"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (is (= asymmetric-keys (jwt-oidc/get-jwks pubkey-cache jwks-uri)))))
    ;; Remember to reset cache before every testing block!
    (swap! pubkey-cache empty)
    (testing "Return cached values"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (let [in-cache-before (cache/has? @pubkey-cache jwks-uri)
              retrieved-1 (jwt-oidc/get-jwks pubkey-cache jwks-uri)
              in-cache-after (cache/has? @pubkey-cache jwks-uri)
              retrieved-2 (jwt-oidc/get-jwks pubkey-cache jwks-uri)
              in-cache-final (cache/has? @pubkey-cache jwks-uri)]
          (is (and (= asymmetric-keys retrieved-1 retrieved-2)
                   (not in-cache-before)
                   in-cache-after
                   in-cache-final)))))
    (swap! pubkey-cache empty)
    (testing "Don't cache JKWS we can't retrieve"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       nil)]
        (let [retrieved (jwt-oidc/get-jwks pubkey-cache jwks-uri)]
          (is (and (nil? retrieved)
                   (not (cache/has? @pubkey-cache jwks-uri)))))))))

(deftest test-validate-single-key
  (let [validate-pubkey rsa-pub-key
        exp (+ (now-in-secs) default-token-ttl)
        default-token-details {:sub sub
                               :iss issuer-url
                               :aud audience
                               :sign-key rsa-priv-key
                               :kid jwk-rsa-kid
                               :alg :rs256
                               :exp exp}
        claims {:iss issuer-url :aud audience}]
    (testing "Successfully validate a token with a specific key"
      (let [token (create-token default-token-details)
            result (jwt-oidc/validate-single-key token validate-pubkey claims)]
        (is (= {:sub sub :exp exp} result))))
    (testing "Fail to validate an expired token"
      (let [exp (- (now-in-secs) 1)
            token (create-token (assoc default-token-details :exp exp))
            result (jwt-oidc/validate-single-key token validate-pubkey claims)]
        (is (= nil result))))
    (testing "Fail to validate a token signed with another key"
      (let [token (create-token (assoc default-token-details
                                       :sign-key ecdsa-priv-key
                                       :kid jwk-ecdsa-kid
                                       :alg :es256))
            result (jwt-oidc/validate-single-key token validate-pubkey claims)]
        (is (= nil result))))
    (testing "Fail to validate a token from another issuer"
      (let [token (create-token (assoc default-token-details
                                       :iss "https://example.invalid/"))
            result (jwt-oidc/validate-single-key token validate-pubkey claims)]
        (is (= nil result))))
    (testing "Fail to validate a token for another audience"
      (let [token (create-token (assoc default-token-details
                                       :aud (str "another-" audience)))
            result (jwt-oidc/validate-single-key token validate-pubkey claims)]
        (is (= nil result))))
    (testing "Fail to validate a token signed with a symmetric key"
      (let [validate-pubkey hs256-key
            token (create-token (assoc default-token-details
                                       :sign-key hs256-key
                                       :kid jwk-hs256-kid
                                       :alg :hs256))
            result (jwt-oidc/validate-single-key token validate-pubkey claims)]
        (is (= nil result))))
    (testing "Fail to validate a token, using invalid key values"
      (let [invalid-keys [1 "invalid"]
            token (create-token default-token-details)
            result (mapv #(jwt-oidc/validate-single-key token % claims) invalid-keys)]
        (is (every? nil? result))))
    (testing "Fail to validate a token, not providing valid params"
      (let [token (create-token default-token-details)
            iss-nil (assoc claims :iss nil)
            aud-nil (assoc claims :aud nil)]
        (is (thrown? ExceptionInfo (jwt-oidc/validate-single-key token nil claims)))
        (is (thrown? ExceptionInfo (jwt-oidc/validate-single-key token validate-pubkey nil)))
        (is (thrown? ExceptionInfo (jwt-oidc/validate-single-key token validate-pubkey iss-nil)))
        (is (thrown? ExceptionInfo (jwt-oidc/validate-single-key token validate-pubkey aud-nil)))))))

(deftest test-validate-token*
  (let [validate-pubkeys [rsa-pub-key ecdsa-pub-key]
        exp (+ (now-in-secs) default-token-ttl)
        default-token-details {:sub sub
                               :iss issuer-url
                               :aud audience
                               :sign-key rsa-priv-key
                               :kid jwk-rsa-kid
                               :alg :rs256
                               :exp exp}
        claims {:iss issuer-url :aud audience}]
    (testing "Successfully validate a token with some key from the Issuer public keys"
      (let [token (create-token default-token-details)
            result (jwt-oidc/validate-token* token validate-pubkeys claims)]
        (is (= {:sub sub :exp exp} result))))
    (testing "Fail to validate an expired token"
      (let [exp (- (now-in-secs) 1)
            token (create-token (assoc default-token-details :exp exp))
            result (jwt-oidc/validate-token* token validate-pubkeys claims)]
        (is (= nil (:sub result)))))
    (testing "Fail to validate a token signed with another key"
      (let [token (create-token (assoc default-token-details
                                       :sign-key hs256-key
                                       :kid jwk-hs256-kid
                                       :alg :hs256))
            result (jwt-oidc/validate-token* token validate-pubkeys claims)]
        (is (= nil (:sub result)))))
    (testing "Fail to validate a token from another issuer"
      (let [token (create-token (assoc default-token-details
                                       :iss "https://example.invalid/"))
            result (jwt-oidc/validate-token* token validate-pubkeys claims)]
        (is (= nil (:sub result)))))
    (testing "Fail to validate a token for another audience"
      (let [token (create-token (assoc default-token-details
                                       :aud (str "another-" audience)))
            result (jwt-oidc/validate-token* token validate-pubkeys claims)]
        (is (= nil (:sub result)))))
    (testing "Fail to validate a token signed with a symmetric key"
      (let [validate-pubkeys (conj validate-pubkeys hs256-key)
            token (create-token (assoc default-token-details
                                       :sign-key hs256-key
                                       :kid jwk-hs256-kid
                                       :alg :hs256))
            result (jwt-oidc/validate-token* token validate-pubkeys claims)]
        (is (= nil (:sub result)))))
    (testing "Fail to validate a token, not providing valid params"
      (let [token (create-token default-token-details)]
        (is (thrown? ExceptionInfo (jwt-oidc/validate-token* token nil claims)))
        (is (thrown? ExceptionInfo (jwt-oidc/validate-token* token -1 claims)))))))

(deftest test-validate-token
  (let [jwk-keys [jwk-rsa jwk-ecdsa jwk-hs256]
        exp (+ (now-in-secs) default-token-ttl)
        default-token-details {:sub sub
                               :iss issuer-url
                               :aud audience
                               :sign-key rsa-priv-key
                               :kid jwk-rsa-kid
                               :alg :rs256
                               :exp exp}
        pubkey-cache (jwt-oidc/create-pubkey-cache jwt-oidc/one-day)
        token-cache (jwt-oidc/create-token-cache 10)
        config {:pubkey-cache pubkey-cache
                :token-cache token-cache
                :jwks-uri jwks-uri
                :claims {:iss issuer-url
                         :aud audience}}]
    (testing "Successfully validate a token with some key from the Issuer public keys, result is cached"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (let [token (create-token default-token-details)
              result (jwt-oidc/validate-token config token)]
          (is (and (= sub result)
                   (cache/has? @token-cache token))))))
    ;; Remember to reset cache before every testing block!
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Fail to validate an expired token, result is cached"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (let [exp (- (now-in-secs) 1)
              token (create-token (assoc default-token-details :exp exp))
              result (jwt-oidc/validate-token config token)]
          (is (and (= nil result)
                   (cache/has? @token-cache token))))))
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Check that valid tokens are not cached after their expiry time"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (let [now (now-in-secs)
              token-1-ttl 4
              token-2-ttl 8
              token-1-exp (+ now token-1-ttl)
              token-2-exp (+ now token-2-ttl)
              token-1 (create-token (assoc default-token-details :exp token-1-exp))
              token-2 (create-token (assoc default-token-details :exp token-2-exp))

              ;; Initial validation
              cached-before-initial-1 (cache/has? @token-cache token-1)
              cached-before-initial-2 (cache/has? @token-cache token-2)
              result-initial-1 (jwt-oidc/validate-token config token-1)
              result-initial-2 (jwt-oidc/validate-token config token-2)
              cached-after-initial-1 (cache/has? @token-cache token-1)
              cached-after-initial-2 (cache/has? @token-cache token-2)

              ;; After wating 2000 ms (less than token-1 and token-2 expiration)
              _ (Thread/sleep 2000)
              cached-before-2000-1 (cache/has? @token-cache token-1)
              cached-before-2000-2 (cache/has? @token-cache token-2)
              result-after-2000-1 (jwt-oidc/validate-token config token-1)
              result-after-2000-2 (jwt-oidc/validate-token config token-2)
              cached-after-2000-1 (cache/has? @token-cache token-1)
              cached-after-2000-2 (cache/has? @token-cache token-2)

              ;; After wating 6000 ms (longer token-1 expiration, but shorter than token-2)
              _ (Thread/sleep 4000)
              cached-before-6000-1 (cache/has? @token-cache token-1)
              cached-before-6000-2 (cache/has? @token-cache token-2)
              result-after-6000-1 (jwt-oidc/validate-token config token-1)
              result-after-6000-2 (jwt-oidc/validate-token config token-2)
              cached-after-6000-1 (cache/has? @token-cache token-1)
              cached-after-6000-2 (cache/has? @token-cache token-2)

              ;; After wating 10000 ms (longer than token-1 and token-2 expiration)
              _ (Thread/sleep 6000)
              cached-before-10000-1 (cache/has? @token-cache token-1)
              cached-before-10000-2 (cache/has? @token-cache token-2)
              result-after-10000-1 (jwt-oidc/validate-token config token-1)
              result-after-10000-2 (jwt-oidc/validate-token config token-2)
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
    (testing "Fail to validate token, no signing keys available, result is not cached"
      (with-redefs [jwt-oidc/get-url (fn [url] nil)]
        (let [token (create-token default-token-details)
              result (jwt-oidc/validate-token config token)]
          (is (and (= nil result)
                   (not (cache/has? @token-cache token)))))))
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Fail to validate a token signed with another key, result is cached"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (let [token (create-token (assoc default-token-details
                                         :sign-key hs256-key
                                         :kid jwk-hs256-kid
                                         :alg :hs256))
              result (jwt-oidc/validate-token config token)]
          (is (and (= nil result)
                   (cache/has? @token-cache token))))))
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Fail to validate a token from another issuer, result is cached"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (let [token (create-token (assoc default-token-details
                                         :iss "https://example.invalid/"))
              result (jwt-oidc/validate-token config token)]
          (is (and (= nil (:sub result))
                   (cache/has? @token-cache token))))))
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Fail to validate a token for another audience, result is cache"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (let [token (create-token (assoc default-token-details
                                         :aud (str "another-" audience)))
              result (jwt-oidc/validate-token config token)]
          (is (and (= nil (:sub result))
                   (cache/has? @token-cache token))))))
    (swap! pubkey-cache empty)
    (swap! token-cache empty)
    (testing "Fail to validate a token, not providing valid params. Result is not cached"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (let [token (create-token default-token-details)
              claims-nil (assoc config :claims nil)
              jwks-uri-nil (assoc config :jwks-uri nil)
              iss-nil (assoc-in config [:claims :iss] nil)
              aud-nil (assoc-in config [:claims :aud] nil)]
          (is (thrown? ExceptionInfo (jwt-oidc/validate-token claims-nil token)))
          (is (not (cache/has? @token-cache token)))
          (is (thrown? ExceptionInfo (jwt-oidc/validate-token jwks-uri-nil token)))
          (is (not (cache/has? @token-cache token)))
          (is (thrown? ExceptionInfo (jwt-oidc/validate-token iss-nil token)))
          (is (not (cache/has? @token-cache token)))
          (is (thrown? ExceptionInfo (jwt-oidc/validate-token aud-nil token)))
          (is (not (cache/has? @token-cache token))))))))

(deftest test-authfn
  (let [jwk-keys [jwk-rsa jwk-ecdsa jwk-hs256]
        now (now-in-secs)
        exp (+ now default-token-ttl)
        default-token-details {:sub sub
                               :iss issuer-url
                               :aud audience
                               :sign-key rsa-priv-key
                               :kid jwk-rsa-kid
                               :alg :rs256
                               :exp exp}
        config {:claims {:iss issuer-url
                         :aud audience}
                :jwks-uri jwks-uri}
        token (create-token default-token-details)]
    (testing "authfn returns a function"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (is (fn? (jwt-oidc/authfn config)))))
    (testing "Success authentication with valid token"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (let [authfn (jwt-oidc/authfn config)]
          (is (= sub (authfn {} token))))))
    (testing "With existig but not expired yet token"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (let [authfn (jwt-oidc/authfn (assoc-in config [:claims :now]
                                                (+ (now-in-secs) thirty-mins)))]
          (is (= sub (authfn {} token))))))
    (testing "With expired token"
      (with-redefs [jwt-oidc/get-url (fn [url]
                                       (json/write-str {:keys jwk-keys}))]
        (let [authfn (jwt-oidc/authfn (assoc-in config [:claims :now]
                                                (+ (now-in-secs) one-day)))]
          (is (= nil (authfn {} token))))))))

(def cognito-user-credentials
  {:username (System/getenv "COGNITO_TESTS_USERNAME")
   :password (System/getenv "COGNITO_TESTS_PASSWORD")
   :subject (System/getenv "COGNITO_TESTS_SUB")})

(def cognito-config
  {:claims {:iss (System/getenv "COGNITO_TESTS_ISSUER_URL")
            :aud (System/getenv "COGNITO_TESTS_AUDIENCE")}
   :jwks-uri (System/getenv "COGNITO_TESTS_JWKS_URI")})

(deftest ^:integration test-cognito-token-validation
  (let [{:keys [username password subject]} cognito-user-credentials
        token (get-cognito-token username password)
        authfn (jwt-oidc/authfn cognito-config)]
    (testing "New valid token"
      (is (= subject (authfn {} token))))
    (testing "With existig but not expired yet token"
      (let [authfn (jwt-oidc/authfn (assoc-in cognito-config [:claims :now]
                                              (+ (now-in-secs) thirty-mins)))]
        (is (= subject (authfn {} token)))))
    (testing "With expired token"
      (let [authfn (jwt-oidc/authfn (assoc-in cognito-config [:claims :now]
                                              (+ (now-in-secs) one-day)))]
        (is (= nil (authfn {} token)))))))
