package auth

import (
    "encoding/json"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/utils"
    "github.com/gravitational/trace"
)

type PocketCertParam struct {
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
    // docker ca pub path
    AuthorityCertFile     string
    // docker Key file path
    NodeEngineKeyFile     string
    // docker cert file path
    NodeEngineCertFile    string
}

// RequestSignedCertificate is used by auth service clients (other services, like proxy or SSH) when a new node joins
// the cluster
func RequestSignedCertificate(param *PocketCertParam) error {
    tok, err := readToken(param.AuthToken)
    if err != nil {
        return trace.Wrap(err)
    }
    method, err := NewTokenAuth(param.HostUUID, tok)
    if err != nil {
        return trace.Wrap(err)
    }

    var servers []utils.NetAddr = param.AuthServers
    client, err := NewTunClient(
        "auth.client.cert.reqsigned",
        servers,
        param.HostUUID,
        method)
    if err != nil {
        return trace.Wrap(err)
    }
    defer client.Close()

    keys, err := requestSignedCertificateWithToken(client, tok, param.Hostname, param.HostUUID, param.Role)
    if err != nil {
        return trace.Wrap(err)
    }
    return writeDockerKeyAndCert(param, keys)
}

// requestSignedCertificateWithToken calls the auth service API to register a new node via registration token which has
// been previously issued via GenerateToken
func requestSignedCertificateWithToken(c *TunClient, token, hostName, hostUUID string, role teleport.Role) (*packedAuthKeyCert, error) {
    out, err := c.PostJSON(apiEndpoint(PocketCertificate, PocketRequestSigned),
        signedCertificateReq{
            Token:       token,
            Hostname:    hostName,
            HostUUID:    hostUUID,
            Role:        role,
        })
    if err != nil {
        return nil, trace.Wrap(err)
    }
    var keys packedAuthKeyCert
    if err := json.Unmarshal(out.Bytes(), &keys); err != nil {
        return nil, trace.Wrap(err)
    }
    return &keys, nil
}
