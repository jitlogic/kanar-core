(defproject kanar/kanar-core "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies
  [[org.clojure/clojure "1.6.0"]
   [org.clojure/data.xml "0.0.8"]
   [ring/ring-core "1.3.2"]
   [slingshot "0.12.2"]
   [compojure "1.3.3"]
   [com.taoensso/timbre "4.0.2"]
   [http-kit "2.1.18"]]
   :profiles
   {:dev {:dependnecies [[compojure "1.3.3"]]}})

