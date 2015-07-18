
(ns kanar.core
  (:require
    [clojure.tools.logging :as log]
    [ring.util.response :refer [redirect]]
    [ring.util.request :refer [body-string]]
    [kanar.core.util :as ku]
    [kanar.core.protocol :as kp]
    [kanar.core.ticket :as kt]
    [slingshot.slingshot :refer [try+ throw+]]
    [org.httpkit.client :as http-kit]
    ;[clj-http.client :as http]
    ))


;Performs authentication and principal resolve.

;Arguments:
;princ - principal data (or null if still not authenticated);
;req - HTTP request object;

;Returns:
;principal object if authentication succeeds

; -------------------------------------------------------------------------------------------------------


(defn form-login-flow [auth-fn render-login-fn]
  ""
  (fn [app-state {{:keys [username password service]} :params :as req}]
    (if (and username password)
      (try+
        (auth-fn nil req)
        (catch [:type :login-failed] {msg :msg}
          (ku/login-cont (render-login-fn :username username :error-msg msg :service service))))
      (ku/login-cont (render-login-fn :service service)))))



(defn form-sulogin-flow [auth-fn su-auth-fn render-su-login-fn]
  ""
  (fn [app-state {{:keys [username password runas service]} :params :as req}]
    (if (and username password runas)
      (try+
        (let [su-princ (su-auth-fn (auth-fn nil req) req)]
          (auth-fn {:id runas :attributes {:impersonificated true, :su-admin username}} req))
        (catch [:type :login-failed] {msg :msg}
          (ku/login-cont (render-su-login-fn :username username :runas runas :error-msg msg :service service))))
      (ku/login-cont (render-su-login-fn :service service)))))



(defn service-allowed [req tgt svc]
  "Decides if user can access given service.

  Arguments:
  req - HTTP request;
  tgt - ticket granting ticket;
  svc - service;
  "
  true)


(defn kanar-service-lookup [services svc-url tgt]
  (if svc-url
    (first
      (for [s services
            :when (re-matches (:url s) svc-url)]
        s))))



(defn kanar-service-redirect
  [{:keys [services ticket-registry render-message-view] :as app-state}  ; :as app-state
   {{service :service target :TARGET :as params} :params :as req}             ; :as req
   tgt]
  (let [svc-url (or service target)
        tid-param (if service "ticket" "SAMLart")
        svc-param (if service "service" "TARGET")]
    (let [svc (kanar-service-lookup services svc-url tgt)]
      (if svc
        (if (contains? params :warn)
          {:status 200
           :body   (render-message-view
                     :ok "Login succesful."
                     :url (str "login?" svc-param "=" svc-url))}  ; TODO safe quotation of service URL
          (if (service-allowed req tgt svc)
            (let [svt (kt/grant-st-ticket ticket-registry svc-url svc tgt)]
              {:status  302
               :body    (render-message-view :ok "Login succesful.")
               :headers {"Location" (str svc-url (if (.contains (:tid svt) "?") "&" "?")
                                         tid-param "=" (:tid svt))}
               :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}})
            {:status  200
             :body    (render-message-view :error "Service not allowed.")
             :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}}))
        {:status  200
         :body    (render-message-view :ok (if svc-url "Invalid service URL." "Login successful."))
         :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}}))))



(defn login-internal
  [auth-flow-fn
   {:keys [ticket-registry] :as app-state}
   {{{CASTGC :value} "CASTGC"} :cookies,
    {:as params} :params :as req}]

  (let [tgc (kt/get-ticket ticket-registry CASTGC)]
    (if (or (contains? params :renew) (empty? tgc))
      (do
        (kt/del-ticket ticket-registry CASTGC)
        (try+
          (let [princ (auth-flow-fn app-state req)
                ticket (kt/grant-tgt-ticket ticket-registry princ)]
            (kanar-service-redirect app-state req ticket))
          (catch [:type :login-cont] {resp :resp} resp)))      ; TODO automated msg <-> resp switching
      (kanar-service-redirect app-state req tgc))))



(defn login-handler [login-flow-fn app-state {{:as params} :params :as req}]
  "Handler for /login and /sulogin requests.

  Arguments:
  app-state - application state
  req - HTTP request
  auth-flow-fn - "
  (let [resp (login-internal login-flow-fn app-state req)]
    (if (and (contains? params :gateway) (not (contains? #{302 401} (:status resp))))
      {:status  302
       :body    "Redirecting ..."
       :headers {"Location" (:service params)}}
      resp)))


(defn service-logout [url svt]
  "Single Sign-Out.

  Arguments:
  url - URL to send;
  svt - service ticket;
  "
  (let [req (http-kit/request
              {:url url
               :method :post
               :user-agent "Kanar CAS Server"
               :headers {}
               :body (kp/cas-logout-msg svt)
               :follow-redirects false
               :keepalive 1000
               :insecure? false})
        res @req]
    (if (not= 200 (:status res))
      (log/warn "Warning: cannot log out session " svt " from service " url ": " (str res)))))


(defn logout-handler
  [{:keys [ticket-registry render-message-view] :as app-state}
   { {service :service} :params, {{CASTGC :value} "CASTGC"} :cookies :as req}]
  (let [tgc (kt/get-ticket ticket-registry CASTGC)]
    (when tgc
      (doseq [{{asu :app-srv-urls} :service, url :url, tid :tid} (kt/session-tickets ticket-registry tgc)]
        (if (empty? asu)
          (service-logout url tid)
          (doseq [url asu] (service-logout url tid))))
      (kt/clear-session ticket-registry CASTGC)))
  (if service
    {:status  302
     :body    "Redirecting to service"
     :headers {"Location" service}}
    {:status 200
     :body (render-message-view :ok "User logged out.")}))


(defn cas10-validate-handler
  [{ticket-registry :ticket-registry}                       ; :as app-state
   {{svc-url :service sid :ticket} :params}]                ; :as req
  (let [svt (kt/get-ticket ticket-registry sid)]                     ; TODO obsłużenie opcji 'renew'
    (kt/del-ticket ticket-registry sid)
    (if (and svc-url sid svt (re-matches #"ST-.*" sid) (= svc-url (:url svt)))
      (str "yes\n" (:id (:princ (:tgt svt))) "\n") "no\n")))


(defn cas20-validate-handler
  [{ticket-registry :ticket-registry :as app-state}          ; :as app-state
   {{svc-url :service sid :ticket pgt-url :pgtUrl} :params}  ; :as req
   re-tid]
  (let [svt (kt/get-ticket ticket-registry sid)]
    (kt/del-ticket ticket-registry sid)
    (cond
      (empty? svc-url)
        (kp/cas20-validate-error "INVALID_REQUEST" "Missing 'service' parameter.")
      (empty? sid)
        (kp/cas20-validate-error "INVALID_REQUEST", "Missing 'ticket' parameter.")
      (not (re-matches re-tid sid))
        (kp/cas20-validate-error "INVALID_TICKET_SPEC" "Invalid ticket.")
      (empty? svt)
        (kp/cas20-validate-error "INVALID_TICKET_SPEC" "Invalid ticket.")
      (not= svc-url (:url svt))
        (kp/cas20-validate-error "INVALID_SERVICE" "Invalid service.")
      (and (not (empty? pgt-url)) (= :svt (:type svt)))
        (if-let [pgt (kt/grant-pgt-ticket ticket-registry svt pgt-url)]
          (kp/cas20-validate-response svt pgt)
          (kp/cas20-validate-error "UNAUTHORIZED_SERVICE_PROXY" "Cannot grant proxy granting ticket."))
      :else
        (kp/cas20-validate-response svt nil))))


(defn proxy-handler
  [{ticket-registry :ticket-registry :as app-state}         ; :as app-state
   {{pgt :pgt svc-url :targetService} :params}]             ; :as req
  (let [ticket (kt/get-ticket ticket-registry pgt)]
    (cond
      (empty? pgt)
        (kp/cas20-proxy-failure "INVALID_REQUEST" "Missing 'pgt' parameter."))
      (empty? svc-url)
        (kp/cas20-proxy-failure "INVALID_REQUEST" "Missing 'targetService' parameter.")
      (not (re-matches #"PGT-.*" pgt))
        (kp/cas20-proxy-failure "BAD_PGT" "Invalid ticket.")
      (empty? ticket)
        (kp/cas20-proxy-failure "BAD_PGT" "Invalid ticket.")
      (not= svc-url (:url pgt))
        (kp/cas20-proxy-failure "INVALID_REQUEST" "Invalid 'targetService' parameter.")
      :else
        (if-let [pt (kt/grant-pt-ticket ticket-registry pgt svc-url)]
          (kp/cas20-proxy-success pt)
          (kp/cas20-proxy-failure "BAD_PGT" "Cannot grant proxy ticket."))))


(defn saml-validate-handler
  [{ticket-registry :ticket-registry}                       ; :as app-state
   {{svc-url :TARGET} :params :as req}]                     ; :as req
  (let [sid (kp/saml-parse-lookup-tid (body-string req)) ; TODO security co z brakujacym lub nieparsowalnym XML ?
        svt (kt/get-ticket ticket-registry sid)]                     ; TODO obsłużenie opcji 'renew'
    (kt/del-ticket ticket-registry sid)
    (if (and svc-url sid svt (re-matches #"ST-.*" sid) (= svc-url (:url svt)))
      (kp/saml-validate-response svt)
      "error executing SAML validation\n")))


(defn ticket-cleaner-task [app-state]
  (future
    (loop []
      (Thread/sleep 30000)
      (try
        (let [ticket-registry (:ticket-registry @app-state)]
          (log/debug "Cleaning up timed out tickets ...")
          (kt/clean-tickets ticket-registry :svt 300000)
          (kt/clean-tickets ticket-registry :pt 300000)
          (kt/clean-tickets ticket-registry :pgt 36000000)
          (kt/clean-tickets ticket-registry :tgt 36000000))
        (catch Throwable e
          (log/error e "Error while cleaning up ticket registry.")))
      (recur))))

