package auth

import (
    "encoding/json"
    "fmt"

    "github.com/gravitational/teleport"
    "github.com/gravitational/trace"
)

type PocketResponseUserIdentity struct {
    LoginName    string    `json:"login"`
    UID          string    `json:"uid"`
    GID          string    `json:"gid"`
}

// requestUserIdentityWithToken calls the auth service API to acquire user information
func requestUserIdentityWithToken(c *TunClient, token, hostName, hostUUID string, role teleport.Role) (*PocketResponseUserIdentity, error) {
    out, err := c.PostJSON(apiEndpoint(PocketOperation, PocketReuqestUserIdentity),
        requestOperationParamWithToken{
            Token:       token,
            Hostname:    hostName,
            HostUUID:    hostUUID,
            Role:        role,
        })
    if err != nil {
        return nil, trace.Wrap(err)
    }
    var user PocketResponseUserIdentity
    if err := json.Unmarshal(out.Bytes(), &user); err != nil {
        return nil, trace.Wrap(err)
    }
    return &user, nil
}

// RequestUserIdentity is used by auth service clients (other services, like proxy or SSH) when a new node joins the cluster
func RequestUserIdentity(param *PocketRequestBase) (*PocketResponseUserIdentity, error) {
    tok, err := readToken(param.AuthToken)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    method, err := NewTokenAuth(param.HostUUID, tok)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    client, err := NewTunClient(
        fmt.Sprintf("auth.client.%s.%s", PocketOperation, PocketReuqestUserIdentity),
        param.AuthServers,
        param.HostUUID,
        method)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    defer client.Close()

    return requestUserIdentityWithToken(client, tok, param.Hostname, param.HostUUID, param.Role)
}
