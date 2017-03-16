package main

import (
    "log"
    "net"

    "github.com/gravitational/teleport/lib/process"

    "github.com/stkim1/pc-node-agent/slcontext"
    "github.com/stkim1/netifaces"
    "github.com/pborman/uuid"
)

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
    err = process.StartNodeTeleport("pc-master", "c9s93fd9-3333-91d3-9999-c9s93fd98f43", true)
    if err != nil {
        log.Print(err.Error())
    }
    slcontext.DebugSlcontextDestroy()
}
