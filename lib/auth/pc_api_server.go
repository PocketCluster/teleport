package auth


import (
    "fmt"
    "net/http"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/httplib"
    "github.com/gravitational/trace"

    "github.com/julienschmidt/httprouter"
    "github.com/stkim1/pcrypto"
)

const (
    PocketApiVersion string     = "v0"

    PocketCertificate string    = "cert"
    PocketRequestSigned string  = "reqsigned"

    PocketUserSignup string     = "signup"
    PocketSignupToken string    = "token"
)

// APIServer implements http API server for AuthServer interface
type PocketAPIServer struct {
    httprouter.Router
    ar *PocketAuthWithRoles
}

// NewAPIServer returns a new instance of APIServer HTTP handler
func NewPocketAPIServer(config *APIConfig, caSigner *pcrypto.CaSigner, role teleport.Role, notFound http.HandlerFunc) PocketAPIServer {
    srv := PocketAPIServer{
        ar: &PocketAuthWithRoles {
            AuthWithRoles: &AuthWithRoles {
                authServer:     config.AuthServer,
                permChecker:    config.PermissionChecker,
                sessions:       config.SessionService,
                role:           role,
                alog:           config.AuditLog,
            },
            caSigner:           caSigner,
        },
    }
    srv.Router   = *httprouter.New()
    srv.NotFound = notFound

    srv.POST(fmt.Sprintf("/%s/%s/%s", PocketApiVersion, PocketCertificate, PocketRequestSigned), httplib.MakeHandler(srv.issueSignedCertificatewithToken))
    srv.POST(fmt.Sprintf("/%s/%s/%s", PocketApiVersion, PocketUserSignup, PocketSignupToken), httplib.MakeHandler(srv.releaseSignupToken))
    return srv
}

type signedCertificateReq struct {
    Token    string        `json:"token"`
    HostID   string        `json:"hostid"`
    Hostname string        `json:"hostname"`
    IP4Addr  string        `json:"ip4addr"`
    Role     teleport.Role `json:"role"`
}

func (s *PocketAPIServer) issueSignedCertificatewithToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) (interface{}, error) {
    var req *signedCertificateReq
    if err := httplib.ReadJSON(r, &req); err != nil {
        return nil, trace.Wrap(err)
    }
    keys, err := s.ar.issueSignedCertificateWithToken(req)
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

func (s *PocketAPIServer) releaseSignupToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) (interface{}, error) {
    var req *signupTokenReq
    if err := httplib.ReadJSON(r, &req); err != nil {
        return nil, trace.Wrap(err)
    }
    tokenData, err := s.ar.releaseSignupToken(req.SignupToken)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    return tokenData, nil
}
