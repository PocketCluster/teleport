package service

import (
    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/defaults"
    "github.com/stkim1/pcrypto"
)

type NodeProperty struct {
    // network ip address of current host
    IP4Addr    string
    // docker ca pub path
    DockerAuthFile string
    // docker Key file path
    DockerKeyFile string
    // docker cert file path
    DockerCertFile string
}

type CoreProperty struct {
    *pcrypto.CaSigner
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
