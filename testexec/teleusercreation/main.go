package main

import (
    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/auth"
    "github.com/gravitational/teleport/lib/service"
    "github.com/gravitational/teleport/lib/services"
    "github.com/gravitational/teleport/embed"

    log "github.com/Sirupsen/logrus"
    "github.com/stkim1/pc-core/context"
    "golang.org/x/crypto/ssh"
)

func createSignupToken(client *auth.TunClient, login string) (string, error) {
    user := services.TeleportUser{
        Name:          login,
        AllowedLogins: []string{login},
    }
    return client.CreateSignupToken(&user)
}

func createUser() {
    context.DebugContextPrepare()
    cfg := service.MakeCoreConfig(true)
    clt, err := embed.OpenAdminClientWithAuthService(&cfg.Config)
    if err != nil {
        log.Error(err.Error())
        return
    }
    defer clt.Close()
    token, err := createSignupToken(clt, "root")
    if err != nil {
        log.Error(err.Error())
        return
    }
    // ed61fba1372a29469e544c6a5aaf5082
    log.Infof("Signup Token %v", token)
    hotpToken, err := auth.RequestHOTPforSignupToken(clt, token)
    if err != nil {
        log.Error(err.Error())
        return
    }
    for _, h := range hotpToken {
        log.Info(h)
    }

    _, err = clt.CreateUserWithToken(token, "1524rmfo", hotpToken[0])
    if err != nil {
        log.Error(err.Error())
        return
    }
}

func create_user_old() {
    context.DebugContextPrepare()
    cfg := service.MakeCoreConfig(true)

    id := auth.IdentityID{HostUUID: cfg.HostUUID, Role: teleport.RoleAdmin}
    identity, err := auth.ReadIdentity(cfg.DataDir, id)
    if err != nil {
        log.Error(err.Error())
        return
    }
    authUser := identity.Cert.ValidPrincipals[0]

    clt, err := auth.NewTunClient(
        string(teleport.RoleAdmin),
        cfg.AuthServers,
        authUser,
        []ssh.AuthMethod{ssh.PublicKeys(identity.KeySigner)},
    )
    // success?
    if err != nil {
        log.Error(err.Error())
        return
    }
    // try calling a test method via auth api:
    //
    // ??? in case of failure it never gets back here!!!
    dn, err := clt.GetDomainName()
    if err != nil {
        log.Error(err.Error())
        return
    }
    // success ? we're logged in!
    log.Infof("[Node] %s connected to the cluster '%s'", authUser, dn)
    //return &service.Connector{Client: authClient, Identity: identity}, nil

/*
    priv, pub, err := clt.GenerateKeyPair("")
    if err != nil {
        log.Error(err.Error())
    }
    // should NOT be able to generate a user cert without basic HTTP auth
    cert, err := clt.GenerateUserCert(pub, "user1", time.Hour)
    if err != nil {
        log.Error(err.Error())
    }
*/

    hotpURL, _, err := clt.UpsertPassword("root", []byte("1524rmfo"))
    if err != nil {
        log.Error(err.Error())
    }
    log.Infof("hotpURL %s", hotpURL)

    user := &services.TeleportUser{Name: "root", AllowedLogins: []string{"root"}}
    err = clt.UpsertUser(user)
    if err != nil {
        log.Error(err.Error())
    }
    clt.DeleteUser("root")
    clt.Close()
}

func delet_user(login string) {
    context.DebugContextPrepare()
    cfg := service.MakeCoreConfig(true)
    clt, err := embed.OpenAdminClientWithAuthService(&cfg.Config)
    if err != nil {
        log.Error(err.Error())
        return
    }
    defer clt.Close()
    clt.DeleteUser("root")
}

func main() {
    delet_user("root")
    createUser()
}
