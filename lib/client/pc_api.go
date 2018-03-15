package client

import (
    "context"
    "fmt"
    "os"
    "io"
    "net"
    "strconv"
    "time"

    "golang.org/x/crypto/ssh"
    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/auth"
    "github.com/gravitational/teleport/lib/defaults"
    "github.com/gravitational/teleport/lib/service"
    "github.com/gravitational/teleport/lib/services"
    "github.com/gravitational/teleport/lib/utils"

    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/trace"
)

// makeClient takes the command-line configuration and constructs & returns
// a fully configured TeleportClient object
func MakeNewClient(cfg *service.PocketConfig, login, targetHost string) (tc *TeleportClient, err error) {
    var labels map[string]string
    fPorts, err := ParsePortForwardSpec([]string{})
    if err != nil {
        return nil, err
    }

    // TODO : shouldn't this be acquired with teleport.RoleNode ???
    id, err := auth.ReadIdentityFromCertStorage(cfg.CoreProperty.CertStorage,
        auth.IdentityID{
            HostUUID: cfg.HostUUID,
            Role: teleport.RoleAdmin})
    if err != nil {
        return nil, trace.Wrap(err)
    }

    // prep client config:
    c := &Config{
        Stdout:             os.Stdout,
        Stderr:             os.Stderr,
        Stdin:              os.Stdin,

        // Equal to SetProxy()
        ProxyHostPort:      fmt.Sprintf("127.0.0.1:%d,%d", defaults.HTTPListenPort, defaults.SSHProxyListenPort),
        // Username is the Teleport user's username (to login into proxies)
        Username:           login,
        // SiteName is equivalient to --cluster argument
        SiteName:           "",
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
        InsecureSkipVerify: false,
        SkipLocalAuth:      false,
        AuthMethods:        []ssh.AuthMethod{ssh.PublicKeys(id.KeySigner)},
        LocalForwardPorts:  fPorts,
        // Interactive, when set to true, launches remote command with the terminal attached
        Interactive:        false,
    }
    return NewPocketClient(c)
}

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

    // sometimes we need to use external auth without using local auth methods, e.g. in automation daemons
    if c.SkipLocalAuth && len(c.AuthMethods) == 0 {
        return nil, trace.BadParameter("SkipLocalAuth is true but no AuthMethods provided")
    }
    return tc, nil
}

// SSH connects to a node and, if 'command' is specified, executes the command on it,
// otherwise runs interactive shell
//
// Returns nil if successful, or (possibly) *exec.ExitError
func (tc *TeleportClient) APISSH(ctx context.Context, command []string, password string, runLocally bool) error {
    // connect to proxy first:
    if !tc.Config.ProxySpecified() {
        return trace.BadParameter("proxy server is not specified")
    }
    proxyClient, err := tc.apiConnectToProxyWithPassword(password, "")
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

// SCP securely copies file(s) from one SSH server to another
func (tc *TeleportClient) APISCP(ctx context.Context, args []string, password string, port int, recursive bool, quiet bool) (err error) {
    if len(args) < 2 {
        return trace.Errorf("Need at least two arguments for scp")
    }
    first := args[0]
    last := args[len(args)-1]

    // local copy?
    if !isRemoteDest(first) && !isRemoteDest(last) {
        return trace.BadParameter("making local copies is not supported")
    }

    if !tc.Config.ProxySpecified() {
        return trace.BadParameter("proxy server is not specified")
    }
    log.Infof("Connecting to proxy to copy (recursively=%v)...", recursive)
    proxyClient, err := tc.apiConnectToProxyWithPassword(password, "")
    if err != nil {
        return trace.Wrap(err)
    }
    defer proxyClient.Close()

    // helper function connects to the src/target node:
    connectToNode := func(addr string) (*NodeClient, error) {
        // determine which cluster we're connecting to:
        siteInfo, err := proxyClient.currentSite()
        if err != nil {
            return nil, trace.Wrap(err)
        }
        return proxyClient.ConnectToNode(ctx, addr+"@"+siteInfo.Name, tc.HostLogin, false)
    }

    var progressWriter io.Writer
    if !quiet {
        progressWriter = tc.Stdout
    }

    // gets called to convert SSH error code to tc.ExitStatus
    onError := func(err error) error {
        exitError, _ := trace.Unwrap(err).(*ssh.ExitError)
        if exitError != nil {
            tc.ExitStatus = exitError.ExitStatus()
        }
        return err
    }
    // upload:
    if isRemoteDest(last) {
        login, host, dest := parseSCPDestination(last)
        if login != "" {
            tc.HostLogin = login
        }
        addr := net.JoinHostPort(host, strconv.Itoa(port))

        client, err := connectToNode(addr)
        if err != nil {
            return trace.Wrap(err)
        }
        // copy everything except the last arg (that's destination)
        for _, src := range args[:len(args)-1] {
            err = client.Upload(src, dest, recursive, tc.Stderr, progressWriter)
            if err != nil {
                return onError(err)
            }
        }
        // download:
    } else {
        login, host, src := parseSCPDestination(first)
        addr := net.JoinHostPort(host, strconv.Itoa(port))
        if login != "" {
            tc.HostLogin = login
        }
        client, err := connectToNode(addr)
        if err != nil {
            return trace.Wrap(err)
        }
        // copy everything except the last arg (that's destination)
        for _, dest := range args[1:] {
            err = client.Download(src, dest, recursive, tc.Stderr, progressWriter)
            if err != nil {
                return onError(err)
            }
        }
    }
    return nil
}

// ConnectToProxy dials the proxy server and returns ProxyClient if successful
func (tc *TeleportClient) apiConnectToProxy() (*ProxyClient, error) {
    var (
        proxyAddr = tc.Config.ProxySSHHostPort()
        sshConfig = &ssh.ClientConfig{
            User:            tc.getProxySSHPrincipal(),
            HostKeyCallback: tc.HostKeyCallback,
        }
        // helper to create a ProxyClient struct
        makeProxyClient = func(sshClient *ssh.Client, m ssh.AuthMethod) *ProxyClient {
            return &ProxyClient{
                Client:          sshClient,
                proxyAddress:    proxyAddr,
                hostKeyCallback: sshConfig.HostKeyCallback,
                authMethod:      m,
                hostLogin:       tc.Config.HostLogin,
                siteName:        tc.Config.SiteName,
            }
        }
    )
    if len(tc.Config.AuthMethods) == 0 {
        return nil, trace.BadParameter("no AuthMethods provided for validating client")
    }

    // After successfull login we have local agent updated with latest
    // and greatest auth information, try it now
    sshConfig.Auth = tc.Config.AuthMethods
    sshConfig.User = tc.getProxySSHPrincipal()
    sshClient, err := ssh.Dial("tcp", proxyAddr, sshConfig)
    if err != nil {
        return nil, trace.Wrap(err)
    }
    proxyClient := makeProxyClient(sshClient, tc.Config.AuthMethods[0])
    // get (and remember) the site info:
    site, err := proxyClient.currentSite()
    if err != nil {
        return nil, trace.Wrap(err)
    }
    tc.SiteName = site.Name
    return proxyClient, nil
}

// ConnectToProxy dials the proxy server and returns ProxyClient if successful
func (tc *TeleportClient) apiConnectToProxyWithPassword(password, encrypted string) (*ProxyClient, error) {
    var (
        proxyAddr = tc.Config.ProxySSHHostPort()
        sshConfig = &ssh.ClientConfig{
            User:            tc.getProxySSHPrincipal(),
            HostKeyCallback: tc.HostKeyCallback,
        }
        // helper to create a ProxyClient struct
        makeProxyClient = func(sshClient *ssh.Client, m ssh.AuthMethod) *ProxyClient {
            return &ProxyClient{
                Client:          sshClient,
                proxyAddress:    proxyAddr,
                hostKeyCallback: sshConfig.HostKeyCallback,
                authMethod:      m,
                hostLogin:       tc.Config.HostLogin,
                siteName:        tc.Config.SiteName,
            }
        }
        successMsg = fmt.Sprintf("[CLIENT] successful auth with proxy %v", proxyAddr)
        authServer = []utils.NetAddr{*defaults.AuthConnectAddr()}
    )

    authMethod, err := tc.requestUserCertificateMethod(authServer, tc.Config.Username, password, encrypted)
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
