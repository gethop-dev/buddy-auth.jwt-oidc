(defproject magnet/buddy-auth.jwt-oidc "0.7.0-SNAPSHOT"
  :description "Buddy-auth JWT token validator, for OpenID Connect ID tokens"
  :url "https://github.com/magnetcoop/buddy-auth.jwt-oidc"
  :license {:name "Mozilla Public Licence 2.0"
            :url "https://www.mozilla.org/en-US/MPL/2.0/"}
  :dependencies [[org.clojure/clojure "1.10.0"]
                 [buddy/buddy-core "1.5.0"]
                 [buddy/buddy-sign "3.0.0"]
                 [diehard "0.7.2"]
                 [duct/core "0.7.0"]
                 [duct/logger "0.3.0"]
                 [http-kit "2.3.0"]
                 [integrant "0.7.0"]
                 [org.clojure/core.cache "0.7.1"]
                 [org.clojure/data.json "0.2.6"]
                 [uk.me.rkd.ttlcache "0.1.0"]]
  :deploy-repositories [["snapshots" {:url "https://clojars.org/repo"
                                      :username :env/clojars_username
                                      :password :env/clojars_password
                                      :sign-releases false}]
                        ["releases"  {:url "https://clojars.org/repo"
                                      :username :env/clojars_username
                                      :password :env/clojars_password
                                      :sign-releases false}]]
  :test-paths ["test"]
  :test-selectors {:default (fn [m] (not (or (:integration m) (:regression m))))
                   :all (constantly true)
                   :integration :integration
                   :regression :regression}
  :profiles
  {:dev {:dependencies [[amazonica "0.3.136" :exclusions [com.amazonaws/aws-java-sdk
                                                          com.amazonaws/amazon-kinesis-client
                                                          com.amazonaws/dynamodb-streams-kinesis-adapter]]
                        [com.amazonaws/aws-java-sdk-cognitoidp "1.11.468"]
                        [com.amazonaws/aws-java-sdk-core "1.11.468"]
                        [com.amazonaws/aws-java-sdk-s3 "1.11.468"]]
           :plugins [[jonase/eastwood "0.3.4"]
                     [lein-cljfmt "0.6.2"]]}
   :repl {:repl-options {:host "0.0.0.0"
                         :port 4001}
          :plugins [[cider/cider-nrepl "0.20.0"]]}})
