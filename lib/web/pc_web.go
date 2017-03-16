package web

import (
    "net/http"
    "strings"

    "github.com/gravitational/teleport/lib/httplib"
    "github.com/gravitational/teleport/lib/utils"
    "github.com/gravitational/trace"

    "github.com/julienschmidt/httprouter"
)

// NewHandler returns a new instance of web proxy handler
func NewPocketHandler(cfg Config, opts ...HandlerOption) (*Handler, error) {
    const (
        apiPrefix = "/" + APIVersion
    )
    lauth, err := newSessionCache([]utils.NetAddr{cfg.AuthServers})
    if err != nil {
        return nil, trace.Wrap(err)
    }
    h := &Handler{
        cfg:  cfg,
        auth: lauth,
    }
    for _, o := range opts {
        if err := o(h); err != nil {
            return nil, trace.Wrap(err)
        }
    }
    if h.sessionStreamPollPeriod == 0 {
        h.sessionStreamPollPeriod = sessionStreamPollPeriod
    }

    // Web sessions
    h.POST("/webapi/sessions", httplib.MakeHandler(h.createSession))
    h.DELETE("/webapi/sessions", h.withAuth(h.deleteSession))
    h.POST("/webapi/sessions/renew", h.withAuth(h.renewSession))

    // Users
    h.GET("/webapi/users/invites/:token", httplib.MakeHandler(h.renderUserInvite))
    h.POST("/webapi/users", httplib.MakeHandler(h.createNewUser))

    // Issues SSH temp certificates upon AES encryption
    h.POST("/webapi/ssh/certs", httplib.MakeHandler(h.createEncryptedSSHCert))

    // list available sites
    h.GET("/webapi/sites", h.withAuth(h.getSites))

    // Site specific API

    // get nodes
    h.GET("/webapi/sites/:site/nodes", h.withSiteAuth(h.getSiteNodes))
    // connect to node via websocket (that's why it's a GET method)
    h.GET("/webapi/sites/:site/connect", h.withSiteAuth(h.siteNodeConnect))
    // get session event stream
    h.GET("/webapi/sites/:site/sessions/:sid/events/stream", h.withSiteAuth(h.siteSessionStream))
    // generate a new session
    h.POST("/webapi/sites/:site/sessions", h.withSiteAuth(h.siteSessionGenerate))
    // update session parameters
    h.PUT("/webapi/sites/:site/sessions/:sid", h.withSiteAuth(h.siteSessionUpdate))
    // get the session list
    h.GET("/webapi/sites/:site/sessions", h.withSiteAuth(h.siteSessionsGet))
    // get a session
    h.GET("/webapi/sites/:site/sessions/:sid", h.withSiteAuth(h.siteSessionGet))
    // get session's events
    h.GET("/webapi/sites/:site/sessions/:sid/events", h.withSiteAuth(h.siteSessionEventsGet))
    // get session's bytestream
    h.GET("/webapi/sites/:site/sessions/:sid/stream", h.siteSessionStreamGet)
    // search site events
    h.GET("/webapi/sites/:site/events", h.withSiteAuth(h.siteEventsGet))

    // OIDC related callback handlers
    h.GET("/webapi/oidc/login/web", httplib.MakeHandler(h.oidcLoginWeb))
    h.POST("/webapi/oidc/login/console", httplib.MakeHandler(h.oidcLoginConsole))
    h.GET("/webapi/oidc/callback", httplib.MakeHandler(h.oidcCallback))

    routingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // request is going to the API?
        if strings.HasPrefix(r.URL.Path, apiPrefix) {
            http.StripPrefix(apiPrefix, h).ServeHTTP(w, r)
            return
        }

        //w.WriteHeader(http.StatusNotImplemented)
        http.NotFound(w, r)
    })
    h.NotFound = routingHandler
    return h, nil
}

// createSSHCert is a web call that generates new SSH certificate based with AES encryption
// on user's name, password, 2nd factor token and public key user wishes to sign
//
// POST /v1/webapi/ssh/certs
//
// { "user": "bob", "password": "pass", "hotp_token": "tok", "pub_key": "key to sign", "ttl": 1000000000 }
//
// Success response
//
// { "cert": "base64 encoded signed cert", "host_signers": [{"domain_name": "example.com", "checking_keys": ["base64 encoded public signing key"]}] }
//
func (h *Handler) createEncryptedSSHCert(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
    var req *createSSHCertReq
    if err := httplib.ReadJSON(r, &req); err != nil {
        return nil, trace.Wrap(err)
    }

    cert, err := h.auth.GetAESEncryptedCertificate(*req)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    return cert, nil
}
