(ns kanar.core.protocol
  (:require
    [clojure.data.xml :as xml]
    [kanar.core.util :as ku]))

(defn emit-xml [el]
  (.substring (xml/emit-str (xml/sexp-as-element el)) 38))

(defn saml-validate-request [tid]
  (let [t1 (ku/xml-time (ku/cur-time))]
    (emit-xml
      [:SOAP-ENV:Envelope {:xmlns:SOAP-ENV "http://schemas.xmlsoap.org/soap/envelope"}
       [:SOAP-ENV:Header]
       [:SOAP-ENV:Body
        [:samlp:Request {:xmlns:samlp  "urn:oasis:names:tc:SAML:1.0:protocol"
                         :MajorVersion "1" :MinorVersion "1"
                         :RequestID    "_192.168.16.51.1024506224022"
                         :IssueInstant t1}
         [:samlp:AssertionArtifact tid]]]])))


(defn saml-validate-response [svt]
  (let [t1 (ku/xml-time (ku/cur-time)), t2 (ku/xml-time (+ 30000 (ku/cur-time)))]
    (emit-xml
      [:SOAP-ENV:Envelope {:xmlns:SOAP-ENV "http://schemas.xmlsoap.org/soap/envelope/"}
       [:SOAP-ENV:Body
        [:saml1p:Response {:xmlns:saml1p  "urn:oasis:names:tc:SAML:1.0:protocol"
                           :IssueInstant t1
                           :MajorVersion "1" :MinorVersion "1"
                           :Recipient    (:url svt)
                           :ResponseId   (str "_" (ku/random-string 32))}
         [:saml1p:Status [:saml1p:StatusCode {:Value "saml1p:Success"}]]
         [:saml1:Assertion
          {:xmlns:saml1        "urn:oasis:names:tc:SAML:1.0:assertion"
           :AssertionID  (str "_" (ku/random-string 32))
           :IssueInstant t1
           :Issuer       "localhost"     ; TODO place correct service name
           :MajorVersion "1" :MinorVersion "1"}
          [:saml1:Conditions {:NotBefore t1, :NotOnOrAfter t2}
           [:saml1:AudienceRestrictionCondition [:saml1:Audience (:url svt)]]]
          [:saml1:AuthenticationStatement
           {:AuthenticationInstant t1
            :AuthenticationMethod  "urn:oasis:names:tc:SAML:1.0:am:unspecified"}
           [:saml1:Subject
            [:saml1:NameIdentifier (get-in svt [:tgt :princ :id])]
            [:saml1:SubjectConfirmation
             [:saml1:ConfirmationMethod "urn:oasis:names:tc:SAML:1.0:cm:artifact"]]]]
          [:saml1:AttributeStatement
           [:saml1:Subject
            [:saml1:NameIdentifier (get-in svt [:tgt :princ :id])]
            [:saml1:SubjectConfirmation
             [:saml1:ConfirmationMethod "urn:oasis:names:tc:SAML:1.0:cm:artifact"]]]
           (for [[k v] (get-in svt [:tgt :princ :attrs])]
             [:saml1:Attribute {:AttributeName (name k)
                          :AttributeNamespace "http://www.ja-sig.org/products/cas"}
              [:saml1:AttributeValue (str v)]])]
          ]]]])))


; TODO potential security concern: stack overflow if parsed XML is too deep
(defn saml-lookup-tid [{:keys [tag content]}]
  (if (= :AssertionArtifact tag)
    (first content)
    (first
      (for [el content
            :when (:tag el)
            :let [tid (saml-lookup-tid el)]
            :when tid]
        tid))))


(defn saml-parse-lookup-tid [body]
  (saml-lookup-tid (xml/parse-str body)))


(defn- cas20 [o]
  (emit-xml [:cas:serviceResponse {:xmlns:cas "http://yale.edu/tp/cas"} o]))


(defn cas-logout-msg [svt]
  (emit-xml
    [:samlp:LogoutRequest {:xmlns:samlp  "urn:oasis:names:tc:SAML:2.0:protocol"
                           :ID           (ku/random-string 32) :Version "2.0"
                           :IssueInstant (ku/xml-time (ku/cur-time))}
     [:saml:NameID {:xmlns:saml "urn:oasis:names:tc:SAML:2.0:assertion"} "@NOT_USED@"]
     [:samlp:SessionIndex svt]]))


(defn cas20-validate-error [code msg]
  (cas20 [:cas:authenticationFailure {:code code} msg]))


(defn cas20-validate-response
  [{{princ :princ} :tgt}
   {iou :iou}]
  (cas20
    [:cas:authenticationSuccess
     [:cas:user (:id princ)]
     (if iou [:cas:proxyGrantingTicket iou])
     (if-not (empty? (:attributes princ))
       [:cas:attributes
        (for [[k v] (:attributes princ)]
          [(keyword (str "cas" k)) v])])]))


(defn cas20-proxy-success [{tid :tid}]
  (cas20 [:cas:proxySuccess [:cas:proxyTicket tid]]))


(defn cas20-proxy-failure [code msg]
  (cas20 [:cas:proxyFailure {:code code} msg]))


