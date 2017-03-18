package main

import (
    "net"
    "os"
    "github.com/gravitational/teleport/lib/service"
    "github.com/gravitational/teleport/lib/process"

    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/trace"
    "github.com/stkim1/pc-node-agent/slcontext"
    "github.com/stkim1/netifaces"
    "github.com/pborman/uuid"
)

func startNodeTeleport(authServerAddr, authToken string, debug bool) error {
    cfg, err := service.MakeNodeConfig(authServerAddr, authToken, debug)
    if err != nil {
        log.Error(err.Error())
        return trace.Wrap(err, "error in initializing teleport")
    }
    // add temporary token
    srv, err := process.NewNodeProcess(cfg)
    if err != nil {
        log.Error(err.Error())
        return trace.Wrap(err, "error in initializing teleport")
    }
    if err := srv.Start(); err != nil {
        log.Error(err.Error())
        return trace.Wrap(err, "starting teleport")
    }
    // create the pid file
    if cfg.PIDFile != "" {
        f, err := os.OpenFile(cfg.PIDFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
        if err != nil {
            log.Error(err.Error())
            return trace.Wrap(err, "failed to create the PID file")
        }
        log.Info(f, "%v", os.Getpid())
        defer f.Close()
    }
    srv.Wait()
    return nil
}

func main() {
    gateway, err := netifaces.FindSystemGateways()
    if err != nil {
        log.Print(err.Error())
    }
    gwaddr, gwiface, err := gateway.DefaultIP4Gateway()
    log.Printf("GW ADDR %s | GW IFACE %s", gwaddr, gwiface)
    _, err = net.InterfaceByName(gwiface)
    if err != nil {
        log.Print(err.Error())
    }
    gateway.Release()

    slcontext.DebugSlcontextPrepare()
    slcontext.SharedSlaveContext().SetSlaveNodeName("pc-node1")
    slcontext.SharedSlaveContext().SetSlaveNodeUUID(uuid.New())
    err = startNodeTeleport("pc-master", "c9s93fd9-3333-91d3-9999-c9s93fd98f43", true)
    if err != nil {
        log.Print(err.Error())
    }
    slcontext.DebugSlcontextDestroy()
}
