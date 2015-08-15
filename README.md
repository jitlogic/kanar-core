# kanar-core

Kanar is a non-reference CAS protocol implementation. Kanar consists of core framework (`kanar-core`),
additional modules (`kanar-ldap`) and a template useful for quick creation of SSO projects.



## Authentication flow

Authentication flow is a function: `(fn [app-state req] ...) -> principal`:

* `app-state` - application state;

* `req` - HTTP request;

* `principal` - returned principal;

Authentication flow can return created (obtained) principal or throw an exception representing login flow change 
(eg. `:login-cont` or `:login-fail`).


## Authenticator functions

Authenticator function: `(fn [princ req] ...) -> principal`:

* `princ` - existing principal or `nil`;

* `req` - HTTP request;

* `principal` - returned principal;

If `princ` is `nil`, authenticator needs to obtain needed credentials from HTTP request and if authenticated, create 
and return principal based on obtained credentials. If `princ` contains existing principal, plugin can either perform 
authorization or provide additional information to processed principal. Authenticator should return created or modified 
principal. Authenticator can throw exceptions representing login flow changes (eg. `:login-fail` or `:login-cont`).


## Application state

Application state map is shared between (most of) significant login flow processing functions. This is a map that
contains the following keys:

* `:ticket-seq` - sequential ticket number; 

* `:ticket-registry` - ticket registry 

* `:services` - service list; 

* `:conf` - application configuration (as loaded from `kanar.conf` file);


## Application configuration

The following settings in application configuration:

* `:server-id` - server ID - a string appended to all generated ticket IDs;

* `:nrepl-enabled`, `:nrepl-port` - 

* `:http-enabled`, `:http-port` - 

* `:https-enabled`, `:https-port`, `:https-keystore`, `:https-keyalias` - 


## Service list

Services list is a vector of service definitions - maps with following keys:

* `:id` - unique ID;

* `:url` - URL mask - this should be regexp object;

* `:app-urls` - (optional) direct URLs to application servers);



## Principal data

Principals are represented as a map with following keys:

* `:id` - principal name (ie. login name);

* `:attributes` - principal attributes (eg. LDAP attributes etc.);

* `:dn` - (optional) DN of an LDAP record (if

Additional keys may appear if needed by application-specific authentication plugins.


# Handling errors and login failures

Kanar uses [https://github.com/scgilardi/slingshot](slingshot) library to throw and handle errors. It allows to 
represent exceptions as clojure data structures and then use pattern matching over thrown structures in catch clauses.

Example error might look like this: `{:type :login-failed, :msg "Invalid username or password."}` 


Errors can have the following attributes:

* `:type` - error type (eg. `:login-failed`, `:login-cont` etc.);

* `:msg` - error message to be composed into standard message view;

* `:msg-args` - map with additional arguments to message view;

* `:body` - response body;

* `:status` - response status;

* `:resp` - whole response struct;

* `:exception` - original exception;


The following standard types are defined:

* `:login-failed` - login failed;

* `:internal-error` - internal error (display 500 page);

* `:login-cont` - login to continue (in multistage authentications, eg. SPNEGO, display form etc.); 


## Service authorization

TBD

## Auditing

TBD



## License

Copyright © 2015 Rafal Lewczuk <rafal.lewczuk@jitlogic.com>

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
