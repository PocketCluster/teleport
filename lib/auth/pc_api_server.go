package auth

import (
    "fmt"
    "net/http"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/httplib"
    "github.com/gravitational/teleport/lib/utils"
    "github.com/gravitational/trace"

    "github.com/julienschmidt/httprouter"
)

const (
    PocketApiVersion          string = "v0"
    PocketUserSignup          string = "signup"
    PocketSignupToken         string = "token"

    PocketOperation           string = "operation"
    PocketRequestSignedCert   string = "reqsignedcert"
    PocketReuqestUserIdentity string = "requserinfo"
)

type PocketRequestBase struct {
    // AuthServers is a list of auth servers nodes, proxies and peer auth servers connect to
    AuthServers           []utils.NetAddr
    // Host role
    Role                  teleport.Role
    // Hostname is a node host name
    Hostname              string
    // HostUUID is a unique host id
    HostUUID              string
    // AuthToken
    AuthToken             string
}

// Enhances API server for pocket API
func enhanceWithPocketAPI(srv *APIServer, config *APIConfig) {
    // (03/11/2017)
    // certSigner is added to issue various types of other certs.
    // We'll later replace it with an enhanced cert manager.
    // Also, it is pointless to add additional APIs without cert signer.
    if config.CertSigner == nil {
        return
    }
    srv.certSigner = config.CertSigner
    srv.userKiosk  = config.UserKiosk

    srv.POST(fmt.Sprintf("/%s/%s/%s", PocketApiVersion, PocketUserSignup, PocketSignupToken),        httplib.MakeHandler(srv.releaseSignupToken))
    srv.POST(fmt.Sprintf("/%s/%s/%s", PocketApiVersion, PocketOperation, PocketRequestSignedCert),   httplib.MakeHandler(srv.issueSignedCertificatewithToken))
    srv.POST(fmt.Sprintf("/%s/%s/%s", PocketApiVersion, PocketOperation, PocketReuqestUserIdentity), httplib.MakeHandler(srv.deliverUserIdentityWithToken))
}

// -- create user with signup token only -- //
// TODO : apply encryption
type signupTokenReq struct {
    SignupToken    string    `json:"signuptoken"`
}

func (s *APIServer) releaseSignupToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) (interface{}, error) {
    var req *signupTokenReq
    if err := httplib.ReadJSON(r, &req); err != nil {
        return nil, trace.Wrap(err)
    }
    tokenData, err := s.a.releaseSignupToken(req.SignupToken)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    return tokenData, nil
}

// -- issue signed certificate with token -- //
type requestOperationParamWithToken struct {
    Token       string           `json:"token"`
    Hostname    string           `json:"hostname"`
    HostUUID    string           `json:"hostuuid"`
    Role        teleport.Role    `json:"role"`
}

func (s *APIServer) issueSignedCertificatewithToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) (interface{}, error) {
    var req *requestOperationParamWithToken
    if err := httplib.ReadJSON(r, &req); err != nil {
        return nil, trace.Wrap(err)
    }
    if s.certSigner == nil {
        return nil, trace.Wrap(fmt.Errorf("Cannot issue certificates with null signer"))
    }
    keys, err := s.a.issueSignedCertificateWithToken(s.certSigner, req)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    return keys, nil
}

// -- deliver user information -- //
func (s *APIServer) deliverUserIdentityWithToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) (interface{}, error) {
    var req *requestOperationParamWithToken
    if err := httplib.ReadJSON(r, &req); err != nil {
        return nil, trace.Wrap(err)
    }
    if s.userKiosk == nil {
        return nil, trace.Wrap(fmt.Errorf("Cannot deliver user identity with null kiosk"))
    }
    return s.a.deliverUserInformationWithToken(s.userKiosk, req)
}
