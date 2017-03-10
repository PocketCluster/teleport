package web

import (
    "crypto/x509"
    "encoding/json"
    "time"

    "github.com/gravitational/trace"
)

// SSHAgentLoginWithAES issues call to web proxy and receives temp certificate
// if credentials encrypted with live AES key are valid
//
// proxyAddr must be specified as host:port
func SSHAgentLoginWithAES(proxyAddr, user, password, encrypted string, pubKey []byte, ttl time.Duration, insecure bool, pool *x509.CertPool) (*SSHLoginResponse, error) {
    clt, _, err := initClient(proxyAddr, insecure, pool)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    re, err := clt.PostJSON(clt.Endpoint("webapi", "ssh", "certs"), createSSHCertReq{
        User:      user,
        Password:  password,
        HOTPToken: encrypted,
        PubKey:    pubKey,
        TTL:       ttl,
    })
    if err != nil {
        return nil, trace.Wrap(err)
    }

    var out *SSHLoginResponse
    err = json.Unmarshal(re.Bytes(), &out)
    if err != nil {
        return nil, trace.Wrap(err)
    }

    return out, nil
}
