package auth

import (
    "fmt"
    "time"
    "strings"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/backend"
    "github.com/gravitational/teleport/lib/services"
    "github.com/gravitational/teleport/lib/services/local"

    "github.com/cloudflare/cfssl/certdb"
    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/trace"
    "github.com/gravitational/teleport/lib/utils"

    "github.com/stkim1/pcrypto"
)

func certAccessorPath(role teleport.Role) (string, string) {
    var(
        keyPath string  = fmt.Sprintf("%s%s%s", teleport.PocketClusterCertPrefix, strings.ToLower(string(role)), pcrypto.FileExtPrivateKey)
        certPath string = fmt.Sprintf("%s%s%s", teleport.PocketClusterCertPrefix, strings.ToLower(string(role)), pcrypto.FileExtCertificate)
    )
    return keyPath, certPath
}

// ReadIdentity reads, parses and returns the given pub/pri key + cert from the
// key storage (dataDir).
func ReadIdentityFromCertStorage(certStorage certdb.Accessor, id IdentityID) (i *Identity, err error) {
    var (
        keyPath, certPath string = certAccessorPath(id.Role)
    )
    log.Debugf("[AUTH] ReadIdentityFromCertStorage, host identity: [key: %v, cert: %v]", keyPath, certPath)

    key, err := certStorage.GetCertificate(keyPath, id.HostUUID)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    if len(key) == 0 {
        return nil, trace.NotFound("Unable to find key %v from certificate storage", keyPath)
    }
    keyBytes := []byte(key[0].PEM)

    cert, err := certStorage.GetCertificate(certPath, id.HostUUID)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    if len(cert) == 0 {
        return nil, trace.NotFound("Unable to find certificate %v from storage", certPath)
    }
    certBytes := []byte(cert[0].PEM)

    return ReadIdentityFromKeyPair(keyBytes, certBytes)
}

// initKeys initializes a nodes host certificate. If the certificate does not exist, a request
// is made to the certificate authority to generate a host certificate and it's written to disk.
// If a certificate exists on disk, it is read in and returned.
func initKeysWithCertStorage(a *AuthServer, certStorage certdb.Accessor, id IdentityID) (*Identity, error) {
    var (
        keyPath, certPath string = certAccessorPath(id.Role)
        keyBytes, certBytes []byte = nil, nil
    )
    log.Debugf("[AUTH] initKeysWithCertStorage, host : [key: %v, cert: %v]", keyPath, certPath)

    key, kerr := certStorage.GetCertificate(keyPath, id.HostUUID)
    if kerr == nil && len(key) != 0 {
        keyBytes = []byte(key[0].PEM)
    }

    cert, cerr := certStorage.GetCertificate(certPath, id.HostUUID)
    if cerr == nil && len(cert) != 0 {
        certBytes = []byte(cert[0].PEM)
    }

    if keyBytes == nil || certBytes == nil {
        packedKeys, err := a.GenerateServerKeys(id.HostUUID, id.NodeName, teleport.Roles{id.Role})
        if err != nil {
            return nil, trace.Wrap(err)
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
            return nil, trace.Wrap(err)
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
            return nil, trace.Wrap(err)
        }
    }
    i, err := ReadIdentityFromCertStorage(certStorage, id)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    return i, nil
}

// Init instantiates and configures an instance of AuthServer
func PocketAuthInit(cfg InitConfig, certStorage certdb.Accessor, seedConfig bool) (*AuthServer, *Identity, error) {
    if cfg.DataDir == "" {
        return nil, nil, trace.BadParameter("DataDir: data dir can not be empty")
    }
    if cfg.HostUUID == "" {
        return nil, nil, trace.BadParameter("HostUUID: host UUID can not be empty")
    }

    lockService := local.NewLockService(cfg.Backend)
    err := lockService.AcquireLock(cfg.DomainName, 60*time.Second)
    if err != nil {
        return nil, nil, err
    }
    defer lockService.ReleaseLock(cfg.DomainName)

    // check that user CA and host CA are present and set the certs if needed
    asrv := NewAuthServer(&cfg)

    // we determine if it's the first start by checking if the CA's are set
    firstStart, err := isFirstStart(asrv, cfg)
    if err != nil {
        return nil, nil, trace.Wrap(err)
    }

    // we skip certain configuration if 'seed_config' is set to true
    // and this is NOT the first time teleport starts on this machine
    skipConfig := seedConfig && !firstStart

    // add trusted authorities from the configuration into the trust backend:
    keepMap := make(map[string]int, 0)
    if !skipConfig {
        for _, ca := range cfg.Authorities {
            if err := asrv.Trust.UpsertCertAuthority(ca, backend.Forever); err != nil {
                return nil, nil, trace.Wrap(err)
            }
            keepMap[ca.DomainName] = 1
        }
    }
    // delete trusted authorities from the trust back-end if they're not
    // in the configuration:
    if !seedConfig {
        hostCAs, err := asrv.Trust.GetCertAuthorities(services.HostCA, false)
        if err != nil {
            return nil, nil, trace.Wrap(err)
        }
        userCAs, err := asrv.Trust.GetCertAuthorities(services.UserCA, false)
        if err != nil {
            return nil, nil, trace.Wrap(err)
        }
        for _, ca := range append(hostCAs, userCAs...) {
            _, configured := keepMap[ca.DomainName]
            if ca.DomainName != cfg.DomainName && !configured {
                if err = asrv.Trust.DeleteCertAuthority(*ca.ID()); err != nil {
                    return nil, nil, trace.Wrap(err)
                }
                log.Infof("removed old trusted CA: '%s'", ca.DomainName)
            }
        }
    }
    // this block will generate user CA authority on first start if it's
    // not currently present, it will also use optional passed user ca keypair
    // that can be supplied in configuration
    if _, err := asrv.GetCertAuthority(services.CertAuthID{DomainName: cfg.DomainName, Type: services.HostCA}, false); err != nil {
        if !trace.IsNotFound(err) {
            return nil, nil, trace.Wrap(err)
        }
        log.Infof("FIRST START: Generating host CA on first start")
        priv, pub, err := asrv.GenerateKeyPair("")
        if err != nil {
            return nil, nil, trace.Wrap(err)
        }
        hostCA := services.CertAuthority{
            DomainName:   cfg.DomainName,
            Type:         services.HostCA,
            SigningKeys:  [][]byte{priv},
            CheckingKeys: [][]byte{pub},
        }
        if err := asrv.Trust.UpsertCertAuthority(hostCA, backend.Forever); err != nil {
            return nil, nil, trace.Wrap(err)
        }
    }
    // this block will generate user CA authority on first start if it's
    // not currently present, it will also use optional passed user ca keypair
    // that can be supplied in configuration
    if _, err := asrv.GetCertAuthority(services.CertAuthID{DomainName: cfg.DomainName, Type: services.UserCA}, false); err != nil {
        if !trace.IsNotFound(err) {
            return nil, nil, trace.Wrap(err)
        }

        log.Infof("FIRST START: Generating user CA on first start")
        priv, pub, err := asrv.GenerateKeyPair("")
        if err != nil {
            return nil, nil, trace.Wrap(err)
        }
        userCA := services.CertAuthority{
            DomainName:   cfg.DomainName,
            Type:         services.UserCA,
            SigningKeys:  [][]byte{priv},
            CheckingKeys: [][]byte{pub},
        }
        if err := asrv.Trust.UpsertCertAuthority(userCA, backend.Forever); err != nil {
            return nil, nil, trace.Wrap(err)
        }
    }

    // (03/17/17)
    // Reverse tunnel (a tunnel between cluster) is not going to be provided as a security measure.

    // (03/17/17)
    // OIDC connectors are removed as it is not necessary as of now. We need to add it back when we need to identity
    // user identification.

    identity, err := initKeysWithCertStorage(
        asrv,
        certStorage,
        IdentityID{HostUUID: cfg.HostUUID,
            NodeName: cfg.NodeName,
            Role: teleport.RoleAdmin})
    if err != nil {
        return nil, nil, trace.Wrap(err)
    }
    return asrv, identity, nil
}

// ReadIdentity reads, parses and returns the given pub/pri key + cert from the key storage (dataDir) for slave node.
func NodeReadIdentityFromFile(keyFilePath, certFilePath string, id IdentityID) (i *Identity, err error) {
    log.Debugf("host identity: [key: %v, cert: %v]", keyFilePath, certFilePath)

    keyBytes, err := utils.ReadPath(keyFilePath)
    if err != nil {
        return nil, trace.Wrap(err)
    }

    certBytes, err := utils.ReadPath(certFilePath)
    if err != nil {
        return nil, trace.Wrap(err)
    }

    return ReadIdentityFromKeyPair(keyBytes, certBytes)
}
