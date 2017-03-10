package service

import (
    "os"
    "fmt"
    "io/ioutil"
    "path/filepath"

    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/teleport/lib/utils"
    "github.com/gravitational/teleport/lib/defaults"
    "github.com/gravitational/trace"

    "github.com/stkim1/pc-core/context"
)

// MakeDefaultConfig creates a new Config structure and populates it with defaults
func MakeCoreConfig(debug bool) *PocketConfig {
    config := &PocketConfig{}
    applyCoreDefaults(config, context.SharedHostContext(), debug)
    return config
}

// Generates a string accepted by the SqliteDB driver, like this:
// `{"path": "/var/lib/teleport/records.db"}`
func sqliteParams(storagePath, dbFile string) string {
    return fmt.Sprintf(`{"path": "%s"}`, filepath.Join(storagePath, dbFile))
}

// applyDefaults applies default values to the existing config structure
func applyCoreDefaults(cfg *PocketConfig, context context.HostContext, debug bool) {
    var (
        hostname, appDataDir, dataDir string = "pc-master", "", ""
        err error = nil
    )

    appDataDir, err = context.ApplicationUserDataDirectory()
    if err != nil {
        log.Errorf("Failed to determine hostname: %v", err)
    }
    dataDir = appDataDir + "/teleport"
    // check if the path exists and make it if absent
    if _, err := os.Stat(dataDir); err != nil {
        if os.IsNotExist(err) {
            os.MkdirAll(dataDir, os.ModeDir|0700);
        }
    }
    caSigner, err := context.MasterCaAuthority()
    if err != nil {
        log.Errorf("Failed to assign cert authority: %v", err)
    }

    cfg.SeedConfig              = false

    // defaults for the auth service:
    cfg.Auth.Enabled            = true
    cfg.AuthServers             = []utils.NetAddr{*defaults.AuthConnectAddr()}
    cfg.Auth.SSHAddr            = *defaults.AuthListenAddr()
    cfg.Auth.EventsBackend.Type = defaults.CoreBackendType
    cfg.Auth.EventsBackend.Params = sqliteParams(dataDir, defaults.CoreEventsSqliteFile)
    cfg.Auth.KeysBackend.Type   = defaults.CoreBackendType
    cfg.Auth.KeysBackend.Params = sqliteParams(dataDir, defaults.CoreKeysSqliteFile)
    cfg.Auth.RecordsBackend.Type = defaults.CoreBackendType
    cfg.Auth.RecordsBackend.Params = sqliteParams(dataDir, defaults.CoreRecordsSqliteFile)
    defaults.ConfigureLimiter(&cfg.Auth.Limiter)

    // defaults for the SSH proxy service:
    cfg.Proxy.Enabled           = true
    // disable web ui as it's not necessary
    // FIXME : check if this is necessary for up and running server
    cfg.Proxy.DisableWebUI      = false
    cfg.Proxy.AssetsDir         = dataDir
    cfg.Proxy.SSHAddr           = *defaults.ProxyListenAddr()
    cfg.Proxy.WebAddr           = *defaults.ProxyWebListenAddr()

    cfg.Proxy.ReverseTunnelListenAddr = *defaults.ReverseTunnellListenAddr()
    defaults.ConfigureLimiter(&cfg.Proxy.Limiter)

    // defaults for the SSH service:
    cfg.SSH.Enabled             = false
    cfg.SSH.Addr                = *defaults.SSHServerListenAddr()
    cfg.SSH.Shell               = defaults.DefaultShell
    defaults.ConfigureLimiter(&cfg.SSH.Limiter)

    // global defaults
    cfg.Hostname                = hostname
    cfg.DataDir                 = dataDir

    // core properties
    cfg.CaSigner                = caSigner

    // debug setup
    if debug {
        cfg.Console = ioutil.Discard
        utils.InitLoggerDebug()
        trace.SetDebug(true)
        log.Info("Teleport DEBUG output configured")
    } else {
        // TODO : check if we can throw debug info
        cfg.Console = os.Stdout
        utils.InitLoggerCLI()
        log.Info("Teleport NORMAL cli output configured")
    }
}

func ValidateCoreConfig(cfg *PocketConfig) error {
    if !cfg.Auth.Enabled && !cfg.SSH.Enabled && !cfg.Proxy.Enabled {
        return trace.BadParameter(
            "config: supply at least one of Auth, SSH or Proxy roles")
    }

    if cfg.DataDir == "" {
        return trace.BadParameter("config: please supply data directory")
    }

    if cfg.Console == nil {
        cfg.Console = ioutil.Discard
    }

    if (cfg.Proxy.TLSKey == "" && cfg.Proxy.TLSCert != "") || (cfg.Proxy.TLSKey != "" && cfg.Proxy.TLSCert == "") {
        return trace.BadParameter("please supply both TLS key and certificate")
    }

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

    return nil
}