// +build darwin
package main

import (
    "database/sql"
    "encoding/json"
    "time"
    "os"
    "path/filepath"

    "github.com/gravitational/teleport/lib/config"
    "github.com/gravitational/teleport/lib/process"
    "github.com/gravitational/teleport/lib/service"
    "github.com/gravitational/teleport/lib/services"
    "github.com/gravitational/trace"

    log "github.com/Sirupsen/logrus"
    _ "github.com/mattn/go-sqlite3"
    "github.com/stkim1/pc-core/context"
    "github.com/stkim1/pcrypto"
)

func createDatabaseInstance(cfg *service.PocketConfig) (*sql.DB, error) {
    type bkcfg struct {
        Path string `json:"path"`
    }

    // initiate sqlite database path
    bc := bkcfg{}
    err := json.Unmarshal([]byte(cfg.Auth.KeysBackend.Params), &bc)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    path, err := filepath.Abs(bc.Path)
    if err != nil {
        return nil, trace.Wrap(err, "failed to convert path")
    }

    // create the data directory if it's missing
    _, err = os.Stat(cfg.DataDir)
    if os.IsNotExist(err) {
        err := os.MkdirAll(cfg.DataDir, os.ModeDir|0700)
        if err != nil {
            return nil, trace.Wrap(err)
        }
    }

    // check if path is ok to use
    dir := filepath.Dir(path)
    s, err := os.Stat(dir)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    if !s.IsDir() {
        return nil, trace.BadParameter("path '%v' should be a valid directory", dir)
    }

    // create database
    db, err := sql.Open("sqlite3", path)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    return db, nil
}

func startCoreProcessTest(cfg *service.PocketConfig, debug bool) error {
    // add static tokens
    for _, token := range []config.StaticToken{"node:d52527f9-b260-41d0-bb5a-e23b0cfe0f8f", "node:c9s93fd9-3333-91d3-9999-c9s93fd98f43"} {
        roles, tokenValue, err := token.Parse()
        if err != nil {
            log.Error(err.Error())
            return trace.Wrap(err)
        }
        cfg.Auth.StaticTokens = append(cfg.Auth.StaticTokens, services.ProvisionToken{Token: tokenValue, Roles: roles, Expires: time.Unix(0, 0)})
    }

    // FIXME : we need to close it when exit application
    // backend & cert storage
    db, err := createDatabaseInstance(cfg)
    if err != nil {
        return trace.Wrap(err)
    }
    // cert engine
    certStorage, err := pcrypto.NewPocketCertStorage(db)
    if err != nil {
        return trace.Wrap(err)
    }
    cfg.CertStorage = certStorage
    // backend storage
    cfg.BackendDB = db

    // new process
    srv, err := process.NewCoreProcess(cfg)
    if err != nil {
        log.Error(err.Error())
        return trace.Wrap(err, "initializing teleport")
    }

    if err := srv.Start(); err != nil {
        log.Error(err.Error())
        return trace.Wrap(err, "starting teleport")
    }
    srv.Wait()
    return nil
}

func main() {
    var debug = true
    context.DebugContextPrepare()
    cfg := service.MakeCoreConfig(debug)

    err := startCoreProcessTest(cfg, debug)
    if err != nil {
        log.Printf("[ERR] %s", err.Error())
    }
}
