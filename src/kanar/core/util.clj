(ns kanar.core.util
  (:import (java.text SimpleDateFormat)
           (java.util Date))
  (:require
    [slingshot.slingshot :refer [try+ throw+]]
    ))


(defn random-string [len]
  "Generates random string of alphanumeric characters of given length."
  (let [s "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]
    (apply str (for [i (range len)] (rand-nth s)))))


(defn cur-time [] (System/currentTimeMillis))

(defn xml-time [t]
  (let [sf (SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSSSZ")]
    (.format sf (Date. t))))

(defn secure-cookie [val]
  {:value val, :http-only true, :secure true})

(defn login-failed [msg]
  (throw+ {:type :login-failed :error msg}))

(defn login-cont [msg]
  (throw+ {:type :login-cont :resp msg}))

(def DEFAULT-CONFIG
  {
   :server-id "SVR1"                                        ; name appended to generated ticket IDs
   :nrepl-enabled false                                     ; enable NREPL port
   :nrepl-port 7700                                         ; NREPL port
   :http-enabled true                                       ; enable HTTP
   :http-port 8080                                          ; HTTP port
   :https-enabled true                                      ; enable HTTPS
   :https-port 8443                                         ; HTTPS port
   })



