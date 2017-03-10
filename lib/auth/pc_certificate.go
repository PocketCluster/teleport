package auth

import (
    "encoding/json"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/utils"
    "github.com/gravitational/trace"
)

type PocketCertParam struct {
    // AuthServers is a list of auth servers nodes, proxies and peer auth servers connect to
    AuthServers []utils.NetAddr
    // Hostname is a node host name
    Hostname        string
    // network ip address of current host
    IP4Addr         string
    // docker ca pub path
    DockerAuthFile  string
    // docker Key file path
    DockerKeyFile   string
    // docker cert file path
    DockerCertFile  string
}

// RequestSignedCertificate is used by auth service clients (other services, like proxy or SSH) when a new node joins
// the cluster
func RequestSignedCertificate(certOpts *PocketCertParam, id IdentityID, token string) error {
    tok, err := readToken(token)
    if err != nil {
        return trace.Wrap(err)
    }
    method, err := NewTokenAuth(id.HostUUID, tok)
    if err != nil {
        return trace.Wrap(err)
    }

    var servers []utils.NetAddr = certOpts.AuthServers
    client, err := NewTunClient(
        "auth.client.cert.reqsigned",
        servers,
        id.HostUUID,
        method)
    if err != nil {
        return trace.Wrap(err)
    }
    defer client.Close()

    keys, err := requestSignedCertificateWithToken(client, tok, id.HostUUID, certOpts.Hostname, certOpts.IP4Addr, id.Role)
    if err != nil {
        return trace.Wrap(err)
    }
    return writeDockerKeyAndCert(certOpts, keys)
}

// requestSignedCertificateWithToken calls the auth service API to register a new node via registration token which has
// been previously issued via GenerateToken
func requestSignedCertificateWithToken(c *TunClient, token, hostID, hostname, ip4Addr string, role teleport.Role) (*packedAuthKeyCert, error) {
    out, err := c.PostJSON(apiEndpoint(PocketCertificate, PocketRequestSigned),
        signedCertificateReq{
            Token:      token,
            HostID:     hostID,
            Hostname:   hostname,
            IP4Addr:    ip4Addr,
            Role:       role,
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
