// +build darwin
package main

import (
    "time"

    "github.com/gravitational/teleport/lib/config"
    "github.com/gravitational/teleport/lib/process"
    "github.com/gravitational/teleport/lib/service"
    "github.com/gravitational/teleport/lib/services"
    "github.com/gravitational/teleport/lib/utils"
    "github.com/gravitational/trace"

    log "github.com/Sirupsen/logrus"
    "github.com/stkim1/pc-core/context"
)

func startCoreProcessTest(cfg *service.PocketConfig) error {
    // add static tokens
    for _, token := range []config.StaticToken{"node:d52527f9-b260-41d0-bb5a-e23b0cfe0f8f", "node:c9s93fd9-3333-91d3-9999-c9s93fd98f43"} {
        roles, tokenValue, err := token.Parse()
        if err != nil {
            log.Error(err.Error())
            return trace.Wrap(err)
        }
        cfg.Auth.StaticTokens = append(cfg.Auth.StaticTokens, services.ProvisionToken{Token: tokenValue, Roles: roles, Expires: time.Unix(0, 0)})
    }
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

func setLogger(debug bool) {
    // debug setup
    if debug {
        utils.InitLoggerDebug()
        trace.SetDebug(true)
        log.Info("Teleport DEBUG output configured")
    } else {
        utils.InitLoggerCLI()
        log.Info("Teleport NORMAL cli output configured")
    }
}

func main() {
    setLogger(true)

    context.DebugContextPrepare()
    // validate configuration
    cfg, err := openConfig()
    if err != nil {
        log.Panic(err)
    }
    err = service.ValidateMasterConfig(cfg)
    if err != nil {
        log.Panic(err)
    }

    err = startCoreProcessTest(cfg)
    if err != nil {
        log.Printf("[ERR] %s", err.Error())
    }
}
