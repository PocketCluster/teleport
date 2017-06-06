package service

import (
    "database/sql"
    "fmt"
    "os"
    "io/ioutil"
    "path/filepath"

    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/teleport/lib/utils"
    "github.com/gravitational/teleport/lib/defaults"
    "github.com/gravitational/trace"

    "github.com/cloudflare/cfssl/certdb"
    "github.com/stkim1/pcrypto"
    "github.com/gravitational/teleport/lib/services"
)

// MakeDefaultConfig creates a new Config structure and populates it with defaults
func MakeCoreConfig(dataDir string, debug bool) *PocketConfig {
    config := &PocketConfig{}
    config.applyCoreDefaults(dataDir)

    // (03/20/2017) Tracer is in debug mode for now
    trace.SetDebug(debug)
    // debug setup
    if debug {
        config.Console = ioutil.Discard
        log.Info("Teleport DEBUG output configured")
    } else {
        // TODO : check if we can throw debug info
        config.Console = os.Stdout
        log.Info("Teleport NORMAL cli output configured")
    }
    return config
}

// applyDefaults applies default values to the existing config structure
func (cfg *PocketConfig) applyCoreDefaults(dataDir string) {
    // defaults for the auth service:
    cfg.SeedConfig                   = false
    cfg.Auth.Enabled                 = true
    cfg.AuthServers                  = []utils.NetAddr{*defaults.AuthConnectAddr()}
    cfg.Auth.SSHAddr                 = *defaults.AuthListenAddr()
    cfg.Auth.EventsBackend.Type      = defaults.CoreBackendType
    cfg.Auth.EventsBackend.Params    = sqliteParams(dataDir, defaults.CoreEventsSqliteFile)
    cfg.Auth.KeysBackend.Type        = defaults.CoreBackendType
    cfg.Auth.KeysBackend.Params      = sqliteParams(dataDir, defaults.CoreKeysSqliteFile)
    cfg.Auth.RecordsBackend.Type     = defaults.CoreBackendType
    cfg.Auth.RecordsBackend.Params   = sqliteParams(dataDir, defaults.CoreRecordsSqliteFile)
    defaults.ConfigureLimiter(&cfg.Auth.Limiter)

    // defaults for the SSH proxy service:
    cfg.Proxy.Enabled                 = true
    // disable web ui as it's not necessary
    cfg.Proxy.DisableWebUI            = true
    cfg.Proxy.AssetsDir               = dataDir
    cfg.Proxy.SSHAddr                 = *defaults.ProxyListenAddr()
    cfg.Proxy.WebAddr                 = *defaults.ProxyWebListenAddr()

    cfg.Proxy.ReverseTunnelListenAddr = *defaults.ReverseTunnellListenAddr()
    defaults.ConfigureLimiter(&cfg.Proxy.Limiter)

    // defaults for the SSH service:
    cfg.SSH.Enabled                   = false
    cfg.SSH.Addr                      = *defaults.SSHServerListenAddr()
    cfg.SSH.Shell                     = defaults.DefaultShell
    defaults.ConfigureLimiter(&cfg.SSH.Limiter)

    // global defaults
    cfg.Hostname                      = defaults.CoreHostName
    cfg.DataDir                       = dataDir
}

func ValidateCoreConfig(cfg *PocketConfig) error {
    if !cfg.Auth.Enabled && !cfg.Proxy.Enabled && cfg.SSH.Enabled {
        return trace.BadParameter(
            "config: supply at least one of Auth, SSH or Proxy roles")
    }
    if cfg.Auth.DomainName == "" {
        return trace.BadParameter("config: please supply domain name")
    }
    if cfg.Hostname == "" {
        return trace.BadParameter("config: please supply core name")
    }
    if cfg.HostUUID == "" {
        return trace.BadParameter("config: please supply host UUID")
    }
    if cfg.DataDir == "" {
        return trace.BadParameter("config: please supply data directory")
    }
    if cfg.Console == nil {
        cfg.Console = ioutil.Discard
    }

/*
    (03/25/2017) TLS keys are not necessary now
    if (cfg.Proxy.TLSKey == "" && cfg.Proxy.TLSCert != "") || (cfg.Proxy.TLSKey != "" && cfg.Proxy.TLSCert == "") {
        return trace.BadParameter("please supply both TLS key and certificate")
    }
*/

    // TODO : COMBINE with PCrypto CA Cert issuer
    if len(cfg.AuthServers) == 0 {
        return trace.BadParameter("auth_servers is empty")
    }
    for i := range cfg.Auth.Authorities {
        if err := cfg.Auth.Authorities[i].Check(); err != nil {
            return trace.Wrap(err)
        }
    }
    for _, tun := range cfg.ReverseTunnels {
        if err := tun.Check(); err != nil {
            return trace.Wrap(err)
        }
    }

    if cfg.BackendDB == nil {
        return trace.BadParameter("please provide database engine for backend storage")
    }
    if cfg.CertStorage == nil {
        return trace.BadParameter("please provide cert storage")
    }
    if cfg.CaSigner == nil {
        return trace.BadParameter("please provide CA signer")
    }
    return nil
}

func (cfg *PocketConfig) AssignHostUUID(uuid string) {
    cfg.HostUUID = uuid
}

func (cfg *PocketConfig) AssignCertStorage(certStorage certdb.Accessor) {
    cfg.CertStorage = certStorage
}

func (cfg *PocketConfig) AssignDatabaseEngine(db *sql.DB) {
    cfg.BackendDB = db
}

func (cfg *PocketConfig) AssignCASigner(caSigner *pcrypto.CaSigner) {
    cfg.CaSigner = caSigner
}

func (cfg *PocketConfig) AssignHostCertAuth(private, sshCheck []byte, domainName string) {
    cfg.Auth.DomainName = domainName
    hostCA := services.CertAuthority{
        DomainName:      domainName,
        Type:            services.HostCA,
        SigningKeys:     [][]byte{private},
        CheckingKeys:    [][]byte{sshCheck},
    }
    cfg.Auth.Authorities = append(cfg.Auth.Authorities, hostCA)
}

// Generates a string accepted by the SqliteDB driver, like this:
// `{"path": "/var/lib/teleport/records.db"}`
func sqliteParams(storagePath, dbFile string) string {
    return fmt.Sprintf(`{"path": "%s"}`, filepath.Join(storagePath, dbFile))
}
