package main

import (
    "context"
    "os"
    "time"

    "github.com/gravitational/teleport/lib/client"
    "github.com/gravitational/teleport/lib/defaults"
    "github.com/gravitational/teleport/lib/utils"

    log "github.com/Sirupsen/logrus"
    "github.com/davecgh/go-spew/spew"
)

// makeClient takes the command-line configuration and constructs & returns
// a fully configured TeleportClient object
func makeClientConfig(login, proxy, targetHost string) *client.Config {
    // prep client config:
    return &client.Config{
        // Username is the Teleport user's username (to login into proxies)
        Username:           login,
        // Target Host to issue SSH command
        Host:               targetHost,
        // Login on a remote SSH host
        HostLogin:          login,
        // HostPort is a remote host port to connect to
        HostPort:           int(defaults.SSHServerListenPort),
        // Proxy keeps the hostname:port of the SSH proxy to use
        ProxyHostPort:      proxy,
        // TTL defines how long a session must be active (in minutes)
        KeyTTL:             time.Minute * time.Duration(defaults.CertDuration / time.Minute),
        // InsecureSkipVerify bypasses verification of HTTPS certificate when talking to web proxy
        InsecureSkipVerify: false,
        // SkipLocalAuth will not try to connect to local SSH agent
        // or use any local certs, and not use interactive logins
        SkipLocalAuth:      false,

        // AuthMethods to use to login into cluster. If left empty, teleport will
        // use its own session store,
        //AuthMethods:

        Stdout:             os.Stdout,
        Stderr:             os.Stderr,
        Stdin:              os.Stdin,
        // Interactive, when set to true, launches remote command with the terminal attached
        Interactive:        false,
    }
}

func main() {
    utils.InitLoggerDebug()

    // "localhost" proxy leads to connect ipv6 address. watchout!
    cfg := makeClientConfig("root", "127.0.0.1", "pc-node1")
    cfg.InsecureSkipVerify = true
    //log.Info(spew.Sdump(cfg))

    clt, err := client.NewPocketClient(cfg)
    if err != nil {
        log.Info(spew.Sdump(err))
        log.Info(err.Error())
        return
    }
    if err = clt.APISSH(context.TODO(), []string{"ls"}, false); err != nil {
        // exit with the same exit status as the failed command:
        if clt.ExitStatus != 0 {
            os.Exit(clt.ExitStatus)
        } else {
            utils.FatalError(err)
        }
    }
}