package web

import (
    "github.com/gravitational/teleport/lib/auth"
    "github.com/gravitational/teleport/lib/services"
    "github.com/gravitational/trace"
)

// This originates from "func (s *sessionCache) GetCertificate(c createSSHCertReq) (*SSHLoginResponse, error)"
func (s *sessionCache) GetAESEncryptedCertificate(c createSSHCertReq) (*SSHLoginResponse, error) {
    method, err := auth.NewWebAESEncryptionAuth(c.User, []byte(c.Password), c.HOTPToken)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    clt, err := auth.NewTunClient("web.session", s.authServers, c.User, method)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    defer clt.Close()
    cert, err := clt.GenerateUserCert(c.PubKey, c.User, c.TTL)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    hostSigners, err := clt.GetCertAuthorities(services.HostCA, false)
    if err != nil {
        return nil, trace.Wrap(err)
    }

    signers := []services.CertAuthority{}
    for _, hs := range hostSigners {
        signers = append(signers, *hs)
    }

    return &SSHLoginResponse{
        Cert:        cert,
        HostSigners: signers,
    }, nil
}