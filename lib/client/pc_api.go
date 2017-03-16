package client

import (
    "context"
    "fmt"
    "os"

    "github.com/gravitational/teleport/lib/auth"
    "github.com/gravitational/teleport/lib/defaults"
    "github.com/gravitational/teleport/lib/services"
    "github.com/gravitational/teleport/lib/utils"

    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/trace"
    "golang.org/x/crypto/ssh"
)

// NewPocketClient creates a TeleportClient object and fully configures it
func NewPocketClient(c *Config) (tc *TeleportClient, err error) {
    // validate configuration
    if c.Username == "" {
        c.Username = Username()
        log.Infof("no teleport login given. defaulting to %s", c.Username)
    }
    if c.ProxyHostPort == "" {
        return nil, trace.Errorf("No proxy address specified, missed --proxy flag?")
    }
    if c.HostLogin == "" {
        c.HostLogin = Username()
        log.Infof("no host login given. defaulting to %s", c.HostLogin)
    }
    if c.KeyTTL == 0 {
        c.KeyTTL = defaults.CertDuration
    } else if c.KeyTTL > defaults.MaxCertDuration || c.KeyTTL < defaults.MinCertDuration {
        return nil, trace.Errorf("invalid requested cert TTL")
    }

    tc = &TeleportClient{Config: *c}

    // initialize the local agent (auth agent which uses local SSH keys signed by the CA):
    tc.localAgent, err = NewPocketLocalAgent(c.Username)
    if err != nil {
        return nil, trace.Wrap(err)
    }

    if tc.Stdout == nil {
        tc.Stdout = os.Stdout
    }
    if tc.Stderr == nil {
        tc.Stderr = os.Stderr
    }
    if tc.Stdin == nil {
        tc.Stdin = os.Stdin
    }
    if tc.HostKeyCallback == nil {
        tc.HostKeyCallback = tc.localAgent.CheckHostSignature
    }

/*
    // sometimes we need to use external auth without using local auth
    // methods, e.g. in automation daemons
    if c.SkipLocalAuth {
        if len(c.AuthMethods) == 0 {
            return nil, trace.BadParameter("SkipLocalAuth is true but no AuthMethods provided")
        }
        return tc, nil
    }
*/
    return tc, nil
}

// SSH connects to a node and, if 'command' is specified, executes the command on it,
// otherwise runs interactive shell
//
// Returns nil if successful, or (possibly) *exec.ExitError
func (tc *TeleportClient) APISSH(ctx context.Context, command []string, runLocally bool) error {
    // connect to proxy first:
    if !tc.Config.ProxySpecified() {
        return trace.BadParameter("proxy server is not specified")
    }
    proxyClient, err := tc.apiConnectToProxy()
    if err != nil {
        return trace.Wrap(err)
    }
    defer proxyClient.Close()
    siteInfo, err := proxyClient.currentSite()
    if err != nil {
        return trace.Wrap(err)
    }
    // which nodes are we executing this commands on?
    nodeAddrs, err := tc.getTargetNodes(ctx, proxyClient)
    if err != nil {
        return trace.Wrap(err)
    }
    if len(nodeAddrs) == 0 {
        return trace.BadParameter("no target host specified")
    }
    // more than one node for an interactive shell?
    // that can't be!
    if len(nodeAddrs) != 1 {
        fmt.Printf(
            "\x1b[1mWARNING\x1b[0m: multiple nodes match the label selector. Picking %v (first)\n",
            nodeAddrs[0])
    }
    nodeClient, err := proxyClient.ConnectToNode(
        ctx,
        nodeAddrs[0]+"@"+siteInfo.Name,
        tc.Config.HostLogin,
        false)
    if err != nil {
        tc.ExitStatus = 1
        return trace.Wrap(err)
    }
    // proxy local ports (forward incoming connections to remote host ports)
    tc.startPortForwarding(nodeClient)

    // local execution?
    if runLocally {
        if len(tc.Config.LocalForwardPorts) == 0 {
            fmt.Println("Executing command locally without connecting to any servers. This makes no sense.")
        }
        return runLocalCommand(command)
    }
    // execute command(s) or a shell on remote node(s)
    if len(command) > 0 {
        return tc.runCommand(ctx, siteInfo.Name, nodeAddrs, proxyClient, command)
    }
    return tc.runShell(nodeClient, nil)
}

// ConnectToProxy dials the proxy server and returns ProxyClient if successful
func (tc *TeleportClient) apiConnectToProxy() (*ProxyClient, error) {
    proxyAddr := tc.Config.ProxySSHHostPort()
    sshConfig := &ssh.ClientConfig{
        User:            tc.getProxySSHPrincipal(),
        HostKeyCallback: tc.HostKeyCallback,
    }
    // helper to create a ProxyClient struct
    makeProxyClient := func(sshClient *ssh.Client, m ssh.AuthMethod) *ProxyClient {
        return &ProxyClient{
            Client:          sshClient,
            proxyAddress:    proxyAddr,
            hostKeyCallback: sshConfig.HostKeyCallback,
            authMethod:      m,
            hostLogin:       tc.Config.HostLogin,
            siteName:        tc.Config.SiteName,
        }
    }
    successMsg := fmt.Sprintf("[CLIENT] successful auth with proxy %v", proxyAddr)

    // we need to ask for the login information
    var username, password, encrypted string = "root", "1524rmfo", "aes-encrypted-message"
    var authServer = []utils.NetAddr{*defaults.AuthConnectAddr()}

    authMethod, err := tc.requestUserCertificateMethod(authServer, username, password, encrypted)
    if err != nil {
        // we need to communicate directly to user here,
        // otherwise user will see endless loop with no explanation
        if trace.IsTrustError(err) {
            fmt.Printf("Refusing to connect to untrusted proxy %v without --insecure flag\n", proxyAddr)
        }
        return nil, trace.Wrap(err)
    }

    // After successfull login we have local agent updated with latest
    // and greatest auth information, try it now
    sshConfig.Auth = []ssh.AuthMethod{authMethod}
    sshConfig.User = tc.getProxySSHPrincipal()
    sshClient, err := ssh.Dial("tcp", proxyAddr, sshConfig)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    log.Debugf(successMsg)
    proxyClient := makeProxyClient(sshClient, authMethod)
    // get (and remember) the site info:
    site, err := proxyClient.currentSite()
    if err != nil {
        return nil, trace.Wrap(err)
    }
    tc.SiteName = site.Name
    return proxyClient, nil
}

func (tc *TeleportClient) requestUserCertificateMethod(authServers []utils.NetAddr, username, passwd, encrypted string) (*CertAuthMethod, error) {
    // generate a new keypair. the public key will be signed via proxy if our password+HOTP  are legit
    key, err := tc.MakeKey()
    if err != nil {
        return nil, trace.Wrap(err)
    }
    method, err := auth.NewWebAESEncryptionAuth(username, []byte(passwd), encrypted)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    clt, err := auth.NewTunClient("api.session", authServers, username, method)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    defer clt.Close()
    cert, err := clt.GenerateUserCert(key.Pub, username, tc.Config.KeyTTL)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    key.Cert = cert

    hostSigners, err := clt.GetCertAuthorities(services.HostCA, false)
    if err != nil {
        return nil, trace.Wrap(err)
    }

    signers := []services.CertAuthority{}
    for _, hs := range hostSigners {
        signers = append(signers, *hs)
    }

    // save the list of CAs we trust to the cache file
    err = tc.localAgent.AddHostSignersToCache(signers)
    if err != nil {
        return nil, trace.Wrap(err)
    }

    // save the key:
    return tc.localAgent.AddKey(tc.ProxyHost(), tc.Config.Username, key)
}
