package auth

import (
    "fmt"
    "strings"

    "github.com/gravitational/teleport"
    "github.com/gravitational/trace"
    "github.com/cloudflare/cfssl/certdb"
)

// LocalRegister is used to generate host keys when a node or proxy is running within the same process
// as the auth server. This method does not need to use provisioning tokens.
func LocalRegisterWithCertStorage(authServer *AuthServer, certStorage certdb.Accessor, id IdentityID) error {
    var (
        kp string = fmt.Sprintf("%s.key", strings.ToLower(string(id.Role)))
        cp string = fmt.Sprintf("%s.cert", strings.ToLower(string(id.Role)))
    )
    packedKeys, err := authServer.GenerateServerKeys(id.HostUUID, id.NodeName, teleport.Roles{id.Role})
    if err != nil {
        return trace.Wrap(err)
    }

    // save key
    err = certStorage.InsertCertificate(certdb.CertificateRecord{
        PEM:        string(packedKeys.Key),
        Serial:     kp,
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
        Serial:     cp,
        AKI:        id.HostUUID,
        Status:     "good",
        Reason:     0,
    })
    if err != nil {
        return trace.Wrap(err)
    }
    return nil
}
