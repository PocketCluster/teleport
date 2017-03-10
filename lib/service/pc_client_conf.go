package service

import (
    "os"
    "time"

    "github.com/gravitational/teleport/lib/client"
    "github.com/gravitational/teleport/lib/defaults"
)

// makeClient takes the command-line configuration and constructs & returns
// a fully configured TeleportClient object
func MakeClientConfig(login, proxy, targetHost string) (tc *client.Config, err error) {
    var labels map[string]string
    fPorts, err := client.ParsePortForwardSpec([]string{})
    if err != nil {
        return nil, err
    }
    // prep client config:
    return &client.Config{
        Stdout:             os.Stdout,
        Stderr:             os.Stderr,
        Stdin:              os.Stdin,
        // Username is the Teleport user's username (to login into proxies)
        Username:           login,
        // Proxy keeps the hostname:port of the SSH proxy to use
        ProxyHostPort:      proxy,
        // Target Host to issue SSH command
        Host:               targetHost,
        // SSH Port on a remote SSH host
        HostPort:           int(defaults.SSHServerListenPort),
        // Login on a remote SSH host
        HostLogin:          login,
        Labels:             labels,
        // TTL defines how long a session must be active (in minutes)
        KeyTTL:             time.Minute * time.Duration(defaults.CertDuration / time.Minute),
        // InsecureSkipVerify bypasses verification of HTTPS certificate when talking to web proxy
        InsecureSkipVerify: true,
        SkipLocalAuth:      false,
        LocalForwardPorts:  fPorts,
        // Interactive, when set to true, launches remote command with the terminal attached
        Interactive:        false,
    }, nil
}