package auth

import (
    "io/ioutil"

    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/teleport"
    "github.com/gravitational/trace"
    "github.com/gravitational/teleport/lib/utils"
    "github.com/cloudflare/cfssl/certdb"
)

// LocalRegister is used to generate host keys when a node or proxy is running within the same process
// as the auth server. This method does not need to use provisioning tokens.
func LocalRegisterWithCertStorage(authServer *AuthServer, certStorage certdb.Accessor, id IdentityID) error {
    var (
        keyPath, certPath string = certAccessorPath(id.Role)
    )
    packedKeys, err := authServer.GenerateServerKeys(id.HostUUID, id.NodeName, teleport.Roles{id.Role})
    if err != nil {
        return trace.Wrap(err)
    }

    // save key
    err = certStorage.InsertCertificate(certdb.CertificateRecord{
        PEM:        string(packedKeys.Key),
        Serial:     keyPath,
        AKI:        id.HostUUID,
        Status:     "good",
        Reason:     0,
    })
    if err != nil {
        return trace.Wrap(err)
    }

    // save cert
    err = certStorage.InsertCertificate(certdb.CertificateRecord{
        PEM:        string(packedKeys.Cert),
        Serial:     certPath,
        AKI:        id.HostUUID,
        Status:     "good",
        Reason:     0,
    })
    if err != nil {
        return trace.Wrap(err)
    }
    return nil
}

// Register is used to generate host keys when a node or proxy are running on different hosts
// than the auth server. This method requires provisioning tokens to prove a valid auth server
// was used to issue the joining request.
func NodeRegister(keyFilePath, certFilePath, token string, id IdentityID, servers []utils.NetAddr) error {
    tok, err := readToken(token)
    if err != nil {
        return trace.Wrap(err)
    }

    // connect to the auth server using a provisioning token. the auth server will
    // only allow you to connect if it's a valid provisioning token it has generated
    method, err := NewTokenAuth(id.HostUUID, tok)
    if err != nil {
        return trace.Wrap(err)
    }
    client, err := NewTunClient(
        "auth.client.noderegister",
        servers,
        id.HostUUID,
        method)
    if err != nil {
        return trace.Wrap(err)
    }
    defer client.Close()

    // create the host certificate and keys
    keys, err := client.RegisterUsingToken(tok, id.HostUUID, id.NodeName, id.Role)
    if err != nil {
        return trace.Wrap(err)
    }
    // write file to location
    log.Debugf("write key to %v, cert to %v", keyFilePath, certFilePath)
    if err := ioutil.WriteFile(keyFilePath, keys.Key, 0600); err != nil {
        return trace.Wrap(err)
    }
    if err := ioutil.WriteFile(certFilePath, keys.Cert, 0600); err != nil {
        return trace.Wrap(err)
    }
    return nil
}
