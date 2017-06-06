package service

import (
    "database/sql"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/defaults"

    "github.com/cloudflare/cfssl/certdb"
    "github.com/stkim1/pcrypto"
)

type NodeProperty struct {
    // network ip address of current host
    IP4Addr                string
    // docker ca pub path
    AuthorityCertFile      string
    // docker Key file path
    NodeEngineKeyFile      string
    // docker cert file path
    NodeEngineCertFile     string
    // node ssh certificate
    NodeSSHCertificateFile string
    // node ssh private key
    NodeSSHPrivateKeyFile  string
}

type CoreProperty struct {
    *pcrypto.CaSigner
    CertStorage certdb.Accessor
    // TODO : (03/18/2017) this need to be removed when CFSSL is incorporated. As of now, certdb's engine is private
    BackendDB *sql.DB
}

// Config structure is used to initialize _all_ services PocketCluster & Teleporot can run.
// Some settings are globl (like DataDir) while others are grouped into sections, like AuthConfig
type PocketConfig struct {
    // original key and cert
    Config
    // Slave node config
    NodeProperty
    // Teleport core config
    CoreProperty
}

// ConfigureSQLite configures SQLite back-ends with a data dir.
func (cfg *Config) ConfigureSQLite() {
    a := &cfg.Auth
    if a.EventsBackend.Type == teleport.SQLiteBackendType {
        a.EventsBackend.Params = sqliteParams(cfg.DataDir, defaults.EventsBoltFile)
    }
    if a.KeysBackend.Type == teleport.SQLiteBackendType {
        a.KeysBackend.Params = sqliteParams(cfg.DataDir, defaults.KeysBoltFile)
    }
    if a.RecordsBackend.Type == teleport.SQLiteBackendType {
        a.RecordsBackend.Params = sqliteParams(cfg.DataDir, defaults.RecordsBoltFile)
    }
}
