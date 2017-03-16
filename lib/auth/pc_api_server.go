package auth


import (
    "fmt"
    "net/http"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/httplib"
    "github.com/gravitational/trace"

    "github.com/julienschmidt/httprouter"
)

const (
    PocketApiVersion string     = "v0"

    PocketCertificate string    = "cert"
    PocketRequestSigned string  = "reqsigned"

    PocketUserSignup string     = "signup"
    PocketSignupToken string    = "token"
)

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

    srv.POST(fmt.Sprintf("/%s/%s/%s", PocketApiVersion, PocketCertificate, PocketRequestSigned), httplib.MakeHandler(srv.issueSignedCertificatewithToken))
    srv.POST(fmt.Sprintf("/%s/%s/%s", PocketApiVersion, PocketUserSignup, PocketSignupToken), httplib.MakeHandler(srv.releaseSignupToken))
}

type signedCertificateReq struct {
    Token    string        `json:"token"`
    HostID   string        `json:"hostid"`
    Hostname string        `json:"hostname"`
    IP4Addr  string        `json:"ip4addr"`
    Role     teleport.Role `json:"role"`
}

func (s *APIServer) issueSignedCertificatewithToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) (interface{}, error) {
    var req *signedCertificateReq
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
