package auth

import (
    "encoding/json"
    "fmt"

    "github.com/gravitational/teleport"
    "github.com/gravitational/trace"
)

type PocketResponseAuthKeyCert struct {
    Auth    []byte    `json:"auth"`
    Key     []byte    `json:"key"`
    Cert    []byte    `json:"cert"`
}

// requestSignedCertificateWithToken calls the auth service API to register a new node via registration token which has
// been previously issued via GenerateToken
func requestSignedCertificateWithToken(c *TunClient, token, hostName, hostUUID string, role teleport.Role) (*PocketResponseAuthKeyCert, error) {
    out, err := c.PostJSON(apiEndpoint(PocketOperation, PocketRequestSignedCert),
        requestOperationParamWithToken{
            Token:       token,
            Hostname:    hostName,
            HostUUID:    hostUUID,
            Role:        role,
        })
    if err != nil {
        return nil, trace.Wrap(err)
    }
    var keys PocketResponseAuthKeyCert
    if err := json.Unmarshal(out.Bytes(), &keys); err != nil {
        return nil, trace.Wrap(err)
    }
    return &keys, nil
}

// RequestSignedCertificate is used by auth service clients (other services, like proxy or SSH) when a new node joins
// the cluster
func RequestSignedCertificate(param *PocketRequestBase) (*PocketResponseAuthKeyCert, error) {
    tok, err := readToken(param.AuthToken)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    method, err := NewTokenAuth(param.HostUUID, tok)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    client, err := NewTunClient(
        fmt.Sprintf("auth.client.%v.%v", PocketOperation, PocketRequestSignedCert),
        param.AuthServers,
        param.HostUUID,
        method)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    defer client.Close()

    return requestSignedCertificateWithToken(client, tok, param.Hostname, param.HostUUID, param.Role)
}
