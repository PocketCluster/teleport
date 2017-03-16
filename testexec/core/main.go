// +build darwin
package main

import (
    "github.com/gravitational/teleport/lib/process"
    "github.com/gravitational/teleport/lib/service"

    "github.com/stkim1/pc-core/context"
    log "github.com/Sirupsen/logrus"
)

func main() {
    var debug = true
    context.DebugContextPrepare()
    cfg := service.MakeCoreConfig(debug)

    err := process.StartCoreProcessTest(cfg, debug)
    if err != nil {
        log.Printf("[ERR] %s", err.Error())
    }
}
