
(ns kanar.core
  (:require
    [taoensso.timbre :as log]
    [ring.util.response :refer [redirect]]
    [ring.util.request :refer [body-string]]
    [kanar.core.util :as ku]
    [kanar.core.protocol :as kp]
    [kanar.core.ticket :as kt]
    [slingshot.slingshot :refer [try+ throw+]]
    [org.httpkit.client :as http-kit]
    ;[clj-http.client :as http]
    ))


(defn audit [{audit-fn :audit-fn :as app-state} req tgt svc action]
  (if audit-fn
    (audit-fn app-state req tgt svc action)
    (log/report "AUDIT:" action "Principal: " (:princ tgt) "Service: " svc)))


(defn form-login-flow [auth-fn render-login-fn]
  "Simple login flow with login form."
  (fn [app-state {{:keys [dom username password service TARGET runas]} :params :as req}]
    (if (and username password)
      (try+
        (let [princ (auth-fn nil req)]
          (audit app-state req {:princ princ} nil :LOGIN-SUCCESS)
          princ)
        (catch [:type :login-failed] {msg :msg :as ex}
          (audit app-state req nil nil :LOGIN-FAILED)
          (log/info "ERROR=" ex)
          (ku/login-cont (render-login-fn :dom dom :username username :runas runas
                                          :error-msg msg :service service, :TARGET TARGET
                                          :req req, :app-state app-state))))
      (ku/login-cont (render-login-fn :dom dom :service service, :TARGET TARGET
                                      :req req, :app-state app-state)))))


(defn service-allowed [{svc-auth-fn :svc-auth-fn} req tgt svc svc-url]
  "Decides if user can access given service."
  (if svc-auth-fn
    (svc-auth-fn req tgt svc svc-url)
    true))


(defn kanar-service-lookup [services svc-url]
  (if svc-url
    (first
      (for [s services
            :when (re-matches (:url s) svc-url)]
        s))))


(defn kanar-service-redirect
  [{:keys [services ticket-registry render-message-view] :as app-state}
   {{:keys [service TARGET] :as params} :params :as req}
   tgt]
  (let [svc-url (or service TARGET)
        tid-param (if service "ticket" "SAMLart")
        svc-param (if service "service" "TARGET")]
    (let [svc (kanar-service-lookup services svc-url)]
      (if svc
        (if (contains? params :warn)
          {:status 200
           :body   (render-message-view                     ; TODO tutaj blad: w tym trybie mamy dziure w bezpieczenstwie
                     :ok "Login succesful."
                     :url (str "login?" svc-param "=" svc-url)
                     :dom (:dom tgt)) :tgt tgt, :req req}  ; TODO safe quotation of service URL
          (if (service-allowed app-state req tgt svc svc-url)
            (let [svt (kt/grant-st-ticket ticket-registry svc-url svc tgt)]
              (audit app-state req tgt svc :SERVICE-TICKET-GRANTED)
              {:status  302
               :body    (render-message-view :ok "Login succesful.", :dom (:dom (:princ tgt)), :req req, :tgt tgt, :app-state app-state)
               :headers {"Location" (str svc-url (if (.contains (:tid svt) "?") "&" "?")
                                         tid-param "=" (:tid svt))}
               :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}})
            (do
              (audit app-state req tgt svc :SERVICE-TICKET-REJECTED)
              {:status  200
               :body    (render-message-view :error "Service not allowed." :dom (:dom (:princ tgt)), :req req, :tgt tgt, :app-state app-state)
               :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}})))
        (do
          (audit app-state req tgt nil :SERVICE-TICKET-REJECTED)
          {:status  200
           :body    (render-message-view :ok (if svc-url "Invalid service URL." "Login successful.")
                                         :dom (:dom (:princ tgt)), :req req, :tgt tgt, :app-state app-state)
           :cookies {"CASTGC" (ku/secure-cookie (:tid tgt))}})))))



(defn login-internal
  [auth-flow-fn
   {:keys [ticket-registry] :as app-state}
   {{{CASTGC :value} "CASTGC"} :cookies,
    {:as params} :params :as req}]

  (let [tgc (kt/get-ticket ticket-registry CASTGC)]
    (if (or (contains? params :renew) (empty? tgc))
      (do
        (let [tgt (kt/get-ticket ticket-registry CASTGC)]
          (if tgt
            (audit app-state req tgt nil :TGT-DESTROYED)
            (kt/del-ticket ticket-registry CASTGC)))
        (try+
          (let [princ (auth-flow-fn app-state req)
                tgt (kt/grant-tgt-ticket ticket-registry princ)]
            (audit app-state req tgt nil :TGT-GRANTED)
            (kanar-service-redirect app-state req tgt))
          (catch [:type :login-cont] {:keys [resp]} resp)
          (catch [:type :login-failed] {:keys [resp]} resp)))
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
   {{service :service} :params, {{CASTGC :value} "CASTGC"} :cookies :as req}]
  (let [tgt (kt/get-ticket ticket-registry CASTGC)]
    (when tgt
      (doseq [{{asu :app-urls} :service, url :url, tid :tid} (kt/session-tickets ticket-registry tgt)]
        (if (empty? asu)
          (service-logout url tid)
          (doseq [url asu] (service-logout url tid))))
      (kt/clear-session ticket-registry CASTGC))
    (if service
      {:status  302
       :body    "Redirecting to service"
       :headers {"Location" service}}
      {:status 200
       :body (render-message-view :ok "User logged out." :dom (:dom (:princ tgt)), :req req, :tgt tgt, :app-state app-state)})))


(defn cas10-validate-handler
  [{ticket-registry :ticket-registry :as app-state}
   {{svc-url :service sid :ticket} :params :as req}]
  (let [svt (kt/get-ticket ticket-registry sid)
        valid (and svc-url sid svt (re-matches #"ST-.*" sid) (= svc-url (:url svt)))] ; TODO obsłużenie opcji 'renew'
    (kt/del-ticket ticket-registry sid)
    (audit app-state req nil nil (if valid :SERVICE-TICKET-VALIDATED :SERVICE-TICKET-NOT-VALIDATED))
    (if valid
      (str "yes\n" (:id (:princ (:tgt svt))) "\n") "no\n")))

; TODO dokończyć auditing (dla wszystkich funkcji poniżej)

(defn cas20-validate-handler
  [{ticket-registry :ticket-registry :as app-state}
   {{svc-url :service sid :ticket pgt-url :pgtUrl} :params :as req}
   re-tid]
  (let [svt (kt/get-ticket ticket-registry sid)]
    (kt/del-ticket ticket-registry sid)
    (cond
      (empty? svc-url)
        (do
          (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (kp/cas20-validate-error "INVALID_REQUEST" "Missing 'service' parameter."))
      (empty? sid)
        (do
          (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (kp/cas20-validate-error "INVALID_REQUEST", "Missing 'ticket' parameter."))
      (not (re-matches re-tid sid))
        (do
          (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (kp/cas20-validate-error "INVALID_TICKET_SPEC" "Invalid ticket."))
      (empty? svt)
        (do
          (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (kp/cas20-validate-error "INVALID_TICKET_SPEC" "Invalid ticket."))
      (not= svc-url (:url svt))
        (do
          (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
          (kp/cas20-validate-error "INVALID_SERVICE" "Invalid service."))
      (and (not (empty? pgt-url)) (= :svt (:type svt)))
        (if-let [pgt (kt/grant-pgt-ticket ticket-registry svt pgt-url)]
          (do
            (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
            (kp/cas20-validate-response svt pgt))
          (do
            (audit app-state req nil nil :SERVICE-TICKET-VALIDATED)
            (kp/cas20-validate-error "UNAUTHORIZED_SERVICE_PROXY" "Cannot grant proxy granting ticket.")))
      :else
        (do
          (audit app-state req nil nil :SERVICE-TICKET-VALIDATED)
          (kp/cas20-validate-response svt nil)))))


(defn proxy-handler
  [{ticket-registry :ticket-registry :as app-state}
   {{pgt :pgt svc-url :targetService} :params :as req}]
  (let [ticket (kt/get-ticket ticket-registry pgt)]
    (cond
      (empty? pgt)
        (do
          (audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (kp/cas20-proxy-failure "INVALID_REQUEST" "Missing 'pgt' parameter."))
      (empty? svc-url)
        (do
          (audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (kp/cas20-proxy-failure "INVALID_REQUEST" "Missing 'targetService' parameter."))
      (not (re-matches #"PGT-.*" pgt))
        (do
          (audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (kp/cas20-proxy-failure "BAD_PGT" "Invalid ticket."))
      (empty? ticket)
        (do
          (audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (kp/cas20-proxy-failure "BAD_PGT" "Invalid ticket."))
      (not= svc-url (:url pgt))
        (do
          (audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
          (kp/cas20-proxy-failure "INVALID_REQUEST" "Invalid 'targetService' parameter."))
      :else
        (if-let [pt (kt/grant-pt-ticket ticket-registry pgt svc-url)]
          (do
            (audit app-state req nil nil :PROXY-TICKET-VALIDATED)
            (kp/cas20-proxy-success pt))
          (do
            (audit app-state req nil nil :PROXY-TICKET-NOT-VALIDATED)
            (kp/cas20-proxy-failure "BAD_PGT" "Cannot grant proxy ticket."))))))


(defn saml-validate-handler
  [{ticket-registry :ticket-registry :as app-state}
   {{svc-url :TARGET} :params :as req}]
  (let [sid (kp/saml-parse-lookup-tid (body-string req)) ; TODO security co z brakujacym lub nieparsowalnym XML ?
        svt (kt/get-ticket ticket-registry sid)]                     ; TODO obsłużenie opcji 'renew'
    (kt/del-ticket ticket-registry sid)
    (if (and svc-url sid svt (re-matches #"ST-.*" sid) (= svc-url (:url svt)))
      (do
        (let [res (kp/saml-validate-response svt)]
          (audit app-state req nil nil :SERVICE-TICKET-VALIDATED)
          (log/info "SAML response: " res)
          res))
      (do
        (audit app-state req nil nil :SERVICE-TICKET-NOT-VALIDATED)
        "error executing SAML validation\n"))))


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


