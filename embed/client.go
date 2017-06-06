package embed

import (
    "golang.org/x/crypto/ssh"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/auth"
    "github.com/gravitational/teleport/lib/defaults"
    "github.com/gravitational/teleport/lib/service"
    "github.com/gravitational/teleport/lib/utils"
    "github.com/gravitational/trace"
)

// connectToAuthService creates a valid client connection to the auth service
func OpenAdminClientWithAuthService(cfg *service.PocketConfig) (client *auth.TunClient, err error) {
    // connect to the local auth server by default:
    cfg.Auth.Enabled = true
    if len(cfg.AuthServers) == 0 {
        cfg.AuthServers = []utils.NetAddr{
            *defaults.AuthConnectAddr(),
        }
    }
    id, err := auth.ReadIdentityFromCertStorage(cfg.CoreProperty.CertStorage,
        auth.IdentityID{
            HostUUID: cfg.HostUUID,
            Role: teleport.RoleAdmin})
    if err != nil {
        return nil, trace.Wrap(err)
    }
    authUser := id.Cert.ValidPrincipals[0]
    client, err = auth.NewTunClient(
        "embed.admin-client",
        cfg.AuthServers,
        authUser,
        []ssh.AuthMethod{ssh.PublicKeys(id.KeySigner)},
    )
    if err != nil {
        return nil, trace.Wrap(err)
    }
    // check connectivity by calling something on a clinet:
    _, err = client.GetDialer()()
    if err != nil {
        return nil, trace.Wrap(err, "Cannot connect to the auth server: %v.\nIs the auth server running on %v?", err, cfg.AuthServers[0].Addr)
    }
    return client, nil
}
