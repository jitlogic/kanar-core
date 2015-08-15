(ns kanar.core.util
  (:import (java.text SimpleDateFormat)
           (java.util Date TimeZone))
  (:require
    [slingshot.slingshot :refer [try+ throw+]]
    [taoensso.timbre :as log]
    [clojure.data.xml :as xml]))


(defn random-string
  "Generates random string of alphanumeric characters of given length."
  ([len]
    (random-string len "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
  ([len s]
    (apply str (for [_ (range len)] (rand-nth s)))))


(defn cur-time [] (System/currentTimeMillis))


(defn xml-time
  ([] (xml-time (.getTime (Date.))))
  ([^Long t]
   (let [sf (SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")]
     (.setTimeZone sf (TimeZone/getTimeZone "UTC"))
     (.format sf (Date. t)))))


(defn- xml-element? [e]
  (and
    (map? e)
    (contains? e :tag)
    (contains? e :content)
    (seq? (:content e))))


(defn xml-to-map [{:keys [tag content]}]
  (let [tc (for [c content] (if (xml-element? c) (xml-to-map c) c))
        tc (if (every? map? tc) [(into (first tc) (rest tc))] tc)
        tc (if (= 1 (count tc)) (first tc) tc)]
    {tag tc}))


(defn emit-xml [el]
  (.substring (xml/emit-str (xml/sexp-as-element el)) 38))


(defn secure-cookie [val]
  {:value val, :http-only true, :secure true})


(defn login-failed [msg]
  (throw+ {:type :login-failed :msg msg}))


(defn chpass-failed [msg]
  (throw+ {:type :chpass-failed :msg msg}))


(defn login-cont [resp]
  (throw+ {:type :login-cont :resp resp}))


(defn fatal-error [msg]
  (throw+ {:type :fatal-error :msg msg}))


(defn log-auth-fn [msg]
  (fn [princ _]
    (log/info msg princ)
    princ))


(defn multidomain-auth-fn [& {:as domains}]
  (fn [princ {{dom :dom} :params :as req}]
    (let [afn (domains dom)]
      (if (fn? afn)
        (afn princ req)
        (login-failed "Invalid login domain.")))))


(defn chain-auth-fn [& auth-fns]
  "Chains several auth functions together. Returns auth function that will sequentially call all passed auth-fn
   and pass result principal to next fn."
  (fn [princ req]
    (loop [[f & fns] auth-fns, p princ]
      (if f (recur fns (f p req)) p))))


(defn const-attr-fn [& {:as attrs}]
  (fn [{:keys [attributes] :as princ} _]
    (assoc princ
      :attributes
      (into (or attributes {}) attrs))))


(defn wrap-set-param [f param pfn]
  ""
  (fn [req]
    (let [val (if (keyword? pfn) pfn (pfn req))]
      (f (assoc-in req [:params param] val)))))


(defn auth-domain-fn [default-dom]
  (fn [princ {{dom :dom} :params}]
    (assoc princ :dom (or dom default-dom))))

