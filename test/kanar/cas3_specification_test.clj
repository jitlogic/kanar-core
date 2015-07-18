(ns kanar.cas3-specification-test
  "CAS 3.0 specification compliance test suite."
  (:require
    [clojure.test :refer :all]
    [compojure.core :refer [routes GET ANY rfn]]
    [compojure.route :refer [not-found]]
    [ring.util.response :refer [redirect]]
    [kanar.core :as kc]
    [kanar.core.protocol :as kp]
    [kanar.core.ticket :as kt]
    [kanar.core.util :as ku]
    [slingshot.slingshot :refer [try+ throw+]]
    ))

; Data and fixture.

(def ^:dynamic *treg-atom* (atom {}))
(def ^:dynamic kanar nil)
(def ^:dynamic *sso-logouts* (atom []))


; TODO config.clj module (with default configuration & default component implementations


; TODO dopisać numerki rozdziałów CAS 3.0 Specification


(def ^:dynamic *test-services*
  [{:id :verboten :url #"https://verboten.com" :verboten true}
   {:id :test1 :url #"https://test1.com" :app-urls [ "http://srv1:8080/test1" "http://srv2:8080/test1" ] }
   {:id :all :url #"https://.*"}])


(defn render-login-view [& {:keys [username error-msg service TARGET]}]
  (str "<html><head><title>Kanar</title></head><body>"
       (if error-msg (str "<div>" error-msg "</div>") "")
       "<form method=\"post\" action=\"login\">"
       "<input type=\"text\" value=\"" (or username "") "\" name=\"username\"/>"
       "<input type=\"password\" name=\"password\"/>"
       "<input type=\"hidden\" name=\"lt\" value=\"lt\"/>"
       (if service (str "<input name=\"service\" type=\"hidden\" value=\"" service "\"/>") "")
       (if TARGET (str "<input name=\"TARGET\" type=\"hidden\" value=\"" TARGET "\"/>") "")
       "<input type=\"submit\" value=\"submit\"/>"
       "</form><body></html>"))

(defn render-message-view [status msg & {:keys [url link]}]
  "Renders message view. This function needs to be reimplemented.

  Arguments:
  status - keyword - :ok, :error
  msg - message text
  url, link - if present, will render link pointing to given URL
  "
  (str
    "<html><head><title>Kanar</title></head><body>"
    msg
    (if url (str "<a href=\"" url "\">" link "</a>"))
    "</body></html>"))


(defn render-su-login-view [& {:keys [username error-msg service TARGET]}]
  (str "<html><head><title>Kanar</title></head><body>"
       (if error-msg (str "<div>" error-msg "</div>") "")
       "<form method=\"post\" action=\"login\">"
       "<input type=\"text\" value=\"" (or username "") "\" name=\"username\"/>"
       "<input type=\"password\" name=\"password\"/>"
       "<input type=\"text\" name=\"runas\"/>"
       "<input type=\"hidden\" name=\"lt\" value=\"lt\"/>"
       (if service (str "<input name=\"service\" type=\"hidden\" value=\"" service "\"/>") "")
       (if TARGET (str "<input name=\"TARGET\" type=\"hidden\" value=\"" TARGET "\"/>") "")
       "<input type=\"submit\" value=\"submit\"/>"
       "</form><body></html>"))


(defn authenticate [princ {{username :username password :password} :params :as req}]
  "Basic authentication function.
  princ - principal data (or null if still not authenticated)
  req - HTTP request object (with form params)
  "
  (if princ
    princ
    (if (= username password)
      {:id username :attributes {}}
      (ku/login-failed "Invalid username or password."))))


(defn su-authenticate [{username :id :as princ} req]
  (if (= "su" username)
    princ
    (ku/login-failed "This user is not authorized to perform SU.")))



; TODO przenieść konsturkcję tego do dedykowanego config namespace;
(defn kanar-routes-new [app-state]
  (routes
    (ANY "/login" req                                       ; TODO ANY -> POST/GET
         (kc/login-handler (kc/form-login-flow authenticate render-login-view) @app-state req))
    (ANY "/sulogin" req                                     ; TODO ograniczyć do POST/GET
         (kc/login-handler (kc/form-sulogin-flow authenticate su-authenticate render-su-login-view) @app-state req))
    (ANY "/logout" req                                      ; TODO ograniczyć do GET
         (kc/logout-handler @app-state req))
    (ANY "/validate" req                                    ; TODO ograniczyć do POST
         (kc/cas10-validate-handler @app-state req))
    (ANY "/serviceValidate" req                             ; TODO ograniczyć do POST
         (kc/cas20-validate-handler @app-state req #"ST-.*"))
    (ANY "/proxyValidate" req                               ; TODO ograniczyć do POST
         (kc/cas20-validate-handler @app-state req #"(ST|PT)-.*"))
    (ANY "/proxy" req                                       ; TODO ograniczyć do POST;
         (kc/proxy-handler @app-state req))
    (ANY "/samlValidate" req
         (kc/saml-validate-handler @app-state req))
    (ANY "/*" []
      (redirect "login"))))


(defn basic-test-fixture [f]
  (reset! *treg-atom* {})
  (reset! *sso-logouts* [])
  (binding [kanar (kanar-routes-new
                    (atom
                      {:ticket-seq      (atom 0)
                       :conf            {:server-id "SVR1"}
                       :services        *test-services*
                       :ticket-registry (kt/atom-ticket-registry *treg-atom* "SVR1")
                       :render-message-view render-message-view
                       }))]
    (with-redefs
      [kc/service-allowed (fn [_ _ svc] (not (:verboten svc)))
       kc/service-logout (fn [_ _] nil)]
      (f))))


(use-fixtures :each basic-test-fixture)



; Utility functions for unit tests

(defn get-tgc [r]
  "Extracts SSO ticket ID from HTTP response."
  (get-in r [:cookies "CASTGC" :value]))


(defn get-rdr [r]
  "Extracts redirection URL from HTTP response."
  (get-in r [:headers "Location"]))

(defn get-ticket [r]
  (let [rdr (get-rdr r)
        m (re-matches #".*ticket=(.*)" rdr)]
    (second m)))


(defn get-samlart [r]
  (let [rdr (get-rdr r)
        m (re-matches #".*SAMLart=(.*)" rdr)]
    (second m)))


(defn dummy-service-logout [url tid]
  (swap! *sso-logouts* #(conj % {:url url :tid tid})))

; Unit Tests

(deftest basic-redirections-test
  (testing "Basic redirection test"
    (let [resp (kanar {:uri "/"})]
      (is (= 302 (:status resp)))
      (is (= "login" (get-rdr resp))))))


(deftest basic-login-logout-test
  (testing "Log in with correct password and then logout"
    (let [r1 (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true"}})]
      (is (= 200 (:status r1)))
      (is (= 1 (count @*treg-atom*)) "Should create exactly one SSO session.")
      (is (not (empty? (get-tgc r1))) "Should return CASTGC cookie.")

      (testing "Logout with no ticket."
        (let [r2 (kanar {:uri "/logout"})]
          (is (= 200 (:status r2)))
          (is (= 1 (count @*treg-atom*)))) "Original CASTGC cookie should still be there.")

      (testing "Logout successfully with existing ticket."
        (let [r2 (kanar {:uri "/logout" :cookies {"CASTGC" {:value (get-tgc r1)}}})]
          (is (= 0 (count @*treg-atom*)))))))

  (testing "Log in with bad password."
    (let [r1 (kanar { :uri "/login" :params {:username "test" :password "bad" :lt "true"}})]
      (is (= 200 (:status r1)))
      (is (= 0 (count @*treg-atom*)) "Should not create SSO session."))))


(deftest basic-login-with-cas-redirection-test
  (testing "Log in with correct password and CAS service redirection."
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true" :service "https://my-app.com"}})]
      (is (= 302 (:status r)) "Should make redirect.")
      (is (get-rdr r))
      (is (re-matches #"https://my-app.com.ticket=ST-.*-SVR1", (get-rdr r)))
      (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket."))))


(deftest basic-login-with-saml-redirection-test
  (testing "Log in with correct password and SAML service redirection."
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true" :TARGET "https://my-app.com"}})]
      (is (= 302 (:status r)) "Should make redirect.")
      (is (get-rdr r))
      (is (re-matches #"https://my-app.com.SAMLart=ST-.*-SVR1", (get-rdr r)))
      (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket."))))


(deftest login-with-redirection-and-warn-screen-test
  (testing "Log in with service redirection and warning screen enabled."
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :service "https://my-app.com" :warn nil}})]
      (is (= 200 (:status r)) "Should not make redirect.")
      (is (re-matches #".*a href=.login.service=https://my-app.com.*", (:body r)))
      (is (= 1 (count @*treg-atom*)) "Should create only ticket granting ticket."))))


(deftest login-check-if-login-form-passes-sso-parameters
  (testing "Open login form and check if service parameter is passed properly."
    (let [r (kanar {:uri "/login" :params {:service "https://my-app.com"}})]
      (is (= 200 (:status r)) "Should return login form")
      (is (re-matches #".*https://my-app.com.*", (:body r))))))


(deftest login-check-if-login-is-bypassed-with-gateway-parameter
  (testing "Try opening login form without credentials and with gateway parameter"
    (let [r (kanar { :uri "/login" :params {:service "https://my-app.com" :gateway nil}})]
      (is (= 302 (:status r)))
      (is (re-matches #"https://my-app.com", (get-rdr r))))))


(deftest login-with-renew-option-test
  (testing "Log in once and then use renew option and check if login form appears."
    (let [r (kanar {:uri "/login" :params {:username "test" :password "test"}})]
      (is (= 1 (count @*treg-atom*)) "New ticket should appear.")
      (let [l (kanar {:uri "/login" :params {:renew nil}
                      :cookies {"CASTGC" {:value (get-tgc r)}}})]
        (is (= 200 (:status l)) "Should ask for login once again")
        (is (= 0 (count @*treg-atom*)) "Old ticket should be removed."))))

  (testing "Log in once, then use renew to log in for the second time."
    (let [r (kanar {:uri "/login" :params {:username "t" :password "t" :renew nil}})]
      (is (= 1 (count @*treg-atom*)) "New ticket should appear.")
      (let [l (kanar {:uri "/login" :params {:username "t" :password "t" :renew nil}
                      :cookies {"CASTGC" {:value (get-tgc r)}}})]
        (is (= 1 (count @*treg-atom*)) "Only new ticket exist (old one removed).")
        (is (not= (get-tgc r) (get-tgc l))))))

  (testing "Log in once, then use both renew and gateway options."
    (let [r (kanar {:uri "/login" :params {:service "https://my-app.com" :renew nil :gateway nil}})]
      (is (= 302 (:status r)) "Should redirect straight to application (no ticket).")
      (is (= "https://my-app.com" (get-rdr r)) "Should immediately redirect to application."))))


(deftest try-login-to-forbidden-service-test
  (testing "Try logging in to a service that is not allowed."
    (let [r (kanar {:uri "/login" :params {:service "https://verboten.com" :username "t" :password "t"}})]
      (is (= 200 (:status r)) "Should not redirect anywhere.")
      (is (re-matches #".*not allowed.*" (:body r))))))


(deftest su-login-with-cas-redirection-test
  (testing "Log in with correct password and CAS service redirection via SU"
    (let [r (kanar { :uri "/sulogin" :params {:username "su" :password "su" :runas "test" :lt "true" :service "https://my-app.com"}})]
      (is (= 302 (:status r)) "Should make redirect.")
      (is (get-rdr r))
      (is (re-matches #"https://my-app.com.ticket=ST-.*-SVR1", (get-rdr r)))
      (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket.")
      (let [tid (get-tgc r)
            tgc (get @*treg-atom* tid)]
        (is (= (:id (:princ tgc)) "test") "Should login as user 'test'"))
      )))

(deftest su-login-without-privileves
  (testing "Log in with correct password but without su privileges"
    (let [r (kanar { :uri "/sulogin" :params {:username "test" :password "test" :runas "test" :lt "true" :service "https://my-app.com"}})]
      (is (= 200 (:status r)) "Should NOT make redirect.")
      (is (nil? (get-rdr r)))
      (is (= 0 (count @*treg-atom*))))))

; TODO zalogować do kilku serwisów (jeden bez jawnego URL, drugi z dwoma jawnymi URL), wylogować, stwierdzić że wylogowanie przyszło;


(deftest basic-login-redirect-logout-check-ticket-cache-test
  (testing "Log in with correct password and CAS service redirection, log out and check if all tickets are remoted."
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true" :service "https://my-app.com"}})]
      (is (= 302 (:status r)) "Should make redirect.")
      (is (get-rdr r))
      (is (re-matches #"https://my-app.com.ticket=ST-.*-SVR1", (get-rdr r)))
      (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket.")
      (kanar {:uri "/logout" :cookies {"CASTGC" {:value (get-tgc r)}}})
      (is (= 0 (count @*treg-atom*))))))


; TODO test na bezpieczne przenoszenie parametru URL przez formatki zalogowania / przekierowania itd.


(deftest login-and-logout-with-service-parameter
  (testing "Log in and then log out with passing 'service' parameter to logout URL"
    (let [r (kanar {:uri "/login" :params {:service "https://my-app.com" :username "t" :password "t"}})
          l (kanar {:uri "/logout" :params {:service "https://other-app.com"} :cookies (:cookies r)})]
      (is (= 302 (:status l)) "Should return redirect status")
      (is (= "https://other-app.com" (get-rdr l)) "Should redirect to given application."))))


(deftest basic-cas10-validate-test
  (testing "Log in with correct password and validate service ticket using CAS 1.0 protocol"
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true" :service "https://my-app"}})]
      (is (get-rdr r) "Location should not be empty.")
      (let [sid (re-find (re-matcher #"ST-.*-SVR1" (get-rdr r)))]
        (is sid "Ticket ID should be extracted here.")
        (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket.")
        (let [v (kanar { :uri "/validate" :params {:service "https://my-app" :ticket "XXX"}})]
          (is (= "no\n" (:body v)) "Should verify ticket negatively."))
        (let [v (kanar { :uri "/validate" :params {:service "https://my-app" :ticket sid}})]
          (is (= "yes\ntest\n" (:body v)) "Should verify ticket positively.")
          (is (= 1 (count @*treg-atom*)) "Should clear service ticket after verification."))))))


(deftest basic-cas20-validate-test
  (testing "Log in with correct password and validate service ticket using CAS 2.0 protocol (no proxies)"
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true" :service "https://my-app"}})]
      (is (get-rdr r) "Location should not be empty.")
      (let [tid (re-find (re-matcher #"ST-.*-SVR1" (get-rdr r)))]
        (is tid "Ticket ID should be extracted here.")
        (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket.")
        (let [v (kanar { :uri "/serviceValidate" :params {:service "https://my-app" :ticket "XXX"}})]
          (is (re-matches #".*INVALID_TICKET_SPEC.*" (:body v))))
        (let [v (kanar { :uri "/serviceValidate" :params {:service "https://my-app" :ticket tid}})]
          (is (re-matches #".*cas:user>test</cas:user.*" (:body v)))
          (is (= 1 (count @*treg-atom*)) "Should clear service ticket after verification."))))))


(deftest basic-saml-validate-test
  (testing "Log in with correct password and validate service ticket using SAML protocol"
    (let [r (kanar { :uri "/login" :params {:username "test" :password "test" :lt "true" :TARGET "https://my-app"}})]
      (is (get-rdr r) "Location should not be empty.")
      (let [sid (get-samlart r)]
        (is sid "Ticket ID should be extracted here.")
        (is (= 2 (count @*treg-atom*)) "Should create SSO ticket and service ticket.")
        (let [v (kanar {:uri "/samlValidate" :params {:TARGET "https://my-app" }
                        :body (kp/saml-validate-request "xxx")})]
          (is (= "error executing SAML validation\n" (:body v))))
        (let [v (kanar {:uri "/samlValidate" :params {:TARGET "https://my-app" }
                        :body (kp/saml-validate-request sid)})]
          (is (re-matches #".*saml1:NameIdentifier.test..saml1:NameIdentifier.*" (:body v)))
          (is (= 1 (count @*treg-atom*)) "Should clear service ticket after verification."))))))


(deftest test-single-sign-out
  (testing "Log in to a service, check single sign out."
    (with-redefs [kc/service-logout dummy-service-logout]
      (let [r1 (kanar {:uri "/login" :params {:username "test" :password "test" :service "https://my-app.com"}})
            _  (kanar {:uri "/logout" :cookies {"CASTGC" {:value (get-tgc r1)}}})
            lo [{:url "https://my-app.com", :tid (get-ticket r1)}]]
        (is (= lo @*sso-logouts*))))))


(deftest test-single-sign-out-with-custom-app-urls
  (testing "Log in to a service, check single sign out for application with custom URLs."
    (with-redefs [kc/service-logout dummy-service-logout]
      (let [r1 (kanar {:uri "/login" :params {:username "test" :password "test" :service "https://test1.com"}})
            _  (kanar {:uri "/logout" :cookies {"CASTGC" {:value (get-tgc r1)}}})
            lo [{:url "http://srv1:8080/test1", :tid (get-ticket r1)}
                {:url "http://srv2:8080/test1", :tid (get-ticket r1)}]]
        (is (= lo @*sso-logouts*))))))


(deftest test-single-sign-out-with-two-services
  (testing "Log in to a service, log in to a second service, sign out from both apps"
    (with-redefs [kc/service-logout dummy-service-logout]
      (let [r1 (kanar {:uri "/login" :params {:username "test" :password "test" :service "https://test1.com"}})
            _  (kanar {:uri "/login" :params {:service "https://my-app.com"} :cookies {"CASTGC" {:value (get-tgc r1)}}})
            _  (kanar {:uri "/logout" :cookies {"CASTGC" {:value (get-tgc r1)}}})]
        (is (= 3 (count @*sso-logouts*)))))))


; TODO test na weryfikacje ticketów CAS1 z opcją renew


; TODO test na weryfikacje ticketów CAS2 z opcją renew


; TODO proxy ticket tests


