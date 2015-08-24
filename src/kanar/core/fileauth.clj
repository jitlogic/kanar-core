(ns kanar.core.fileauth
  (:require [kanar.core.util :as ku])
  (:import (java.io File)
           (java.security MessageDigest)))


(defn- load-pwd-file [^String path]
  (let [users (read-string (slurp path))]
    ; TODO sanity check for user data
    {:path path, :fstamp (.lastModified (File. path)), :users users}))


(defn lookup-user [fdb-state username]
  (first (for [{id :id :as u} (:users fdb-state) :when (= id username)] u)))


(def sha2-format (apply str (for [_ (range 32)] "%02x")))

(defn sha2 [^String s]
  (let [d (.digest (MessageDigest/getInstance "SHA-256") (.getBytes s))]
    (String/format sha2-format (to-array (for [b d] b)))))

(defn check-password [pwd-hash password]
  (cond
    (re-matches #"SHA:[0-9a-f]{64}" pwd-hash)
      (= (.substring pwd-hash 4) (sha2 password))
    (re-matches #"SHS:[0-9a-f]{64}" pwd-hash)
      (some #(= (.substring pwd-hash 4) (sha2 (str password %))) (range 2048))
    :else
      (= pwd-hash password)))


(defn file-auth-fn [fdb-state path]
  "Returns file authenticator. "
  (reset! fdb-state (load-pwd-file path))
  (fn [_ {{username :username password :password} :params}]
    (let [princ (lookup-user @fdb-state username)]
      (if (or (nil? princ) (not (check-password (:password princ) password)))
        (ku/login-failed "Invalid username or password."))
      (dissoc princ :password))))


(defn file-lookup-fn [fdb-state path]
  (reset! fdb-state (load-pwd-file path))
  (fn [{:keys [id] :as princ} _]
    (let [princ (lookup-user @fdb-state id)]
      (if-not princ
        (ku/login-failed "Invalid username or password."))
      (dissoc princ :password))))

