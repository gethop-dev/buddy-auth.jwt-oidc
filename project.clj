(defproject dev.gethop/buddy-auth.jwt-oidc "0.10.6-SNAPSHOT"
  :description "Buddy-auth JWT token validator, for OpenID Connect ID tokens"
  :url "https://github.com/gethop-dev/buddy-auth.jwt-oidc"
  :min-lein-version "2.9.8"
  :license {:name "Mozilla Public Licence 2.0"
            :url "https://www.mozilla.org/en-US/MPL/2.0/"}
  :dependencies [[org.clojure/clojure "1.10.0"]
                 [buddy/buddy-core "1.10.413"]
                 [buddy/buddy-sign "3.4.333"]
                 [diehard "0.11.6"]
                 [duct/logger "0.3.0"]
                 [http-kit "2.6.0"]
                 [integrant "0.8.0"]
                 [org.clojure/core.cache "1.0.225"]
                 [org.clojure/data.json "2.4.0"]
                 [coop.magnet/ttlcache "0.2.0"]]
  :deploy-repositories [["snapshots" {:url "https://clojars.org/repo"
                                      :username :env/CLOJARS_USERNAME
                                      :password :env/CLOJARS_PASSWORD
                                      :sign-releases false}]
                        ["releases"  {:url "https://clojars.org/repo"
                                      :username :env/CLOJARS_USERNAME
                                      :password :env/CLOJARS_PASSWORD
                                      :sign-releases false}]]
  :test-paths ["test"]
  :test-selectors {:default (fn [m] (not (or (:integration m) (:regression m))))
                   :all (constantly true)
                   :integration :integration
                   :regression :regression}
  :profiles
  {:dev [:project/dev :profiles/dev]
   :repl {:repl-options {:host "0.0.0.0"
                         :port 4001}}
   :profiles/dev {}
   :project/dev {:dependencies [[amazonica "0.3.143" :exclusions [com.amazonaws/aws-java-sdk
                                                                  com.amazonaws/amazon-kinesis-client
                                                                  com.amazonaws/dynamodb-streams-kinesis-adapter]]
                                [com.amazonaws/aws-java-sdk-cognitoidp "1.11.586"]
                                [com.amazonaws/aws-java-sdk-core "1.11.586"]
                                [com.amazonaws/aws-java-sdk-s3 "1.11.586"]]
                 :plugins [[jonase/eastwood "1.2.3"]
                           [lein-cljfmt "0.8.0"]]}})
