package embed

import (
    "time"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/auth"
    "github.com/gravitational/teleport/lib/defaults"
    "github.com/gravitational/teleport/lib/limiter"
    "github.com/gravitational/teleport/lib/srv"
    "github.com/gravitational/teleport/lib/service"
    "github.com/gravitational/teleport/lib/utils"
    pervice "github.com/stkim1/pc-node-agent/service"

    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/trace"
    "golang.org/x/crypto/ssh"
)

// NewTeleport takes the daemon configuration, instantiates all required services, but does not run service
func NewEmbeddedNodeProcess(sup pervice.AppSupervisor, cfg *service.PocketConfig) (*EmbeddedNodeProcess, error) {
    return &EmbeddedNodeProcess{
        AppSupervisor:    sup,
        config:           cfg,
    }, nil
}

// TeleportProcess structure holds the state of the Teleport daemon, controlling
// execution and configuration of the teleport services: ssh, auth and proxy.
type EmbeddedNodeProcess struct {
    pervice.AppSupervisor
    config *service.PocketConfig
}

func (p *EmbeddedNodeProcess) Close() error {
    p.BroadcastEvent(pervice.Event{Name:service.TeleportExitEvent})
    return nil
}

// connectToAuthService attempts to login into the auth servers specified in the
// configuration. Returns 'true' if successful
func (p *EmbeddedNodeProcess) connectToAuthService(role teleport.Role) (*service.Connector, error) {
    var (
        cfg = p.config
        id = auth.IdentityID{HostUUID: p.config.HostUUID, Role: role}
    )

    identity, err := auth.NodeReadIdentityFromFile(cfg.NodeSSHPrivateKeyFile, cfg.NodeSSHCertificateFile, id)
    if err != nil {
        return nil, trace.Wrap(err)
    }

    authUser := identity.Cert.ValidPrincipals[0]
    authClient, err := auth.NewTunClient(
        string(role),
        p.config.AuthServers,
        authUser,
        []ssh.AuthMethod{ssh.PublicKeys(identity.KeySigner)},
    )
    // success?
    if err != nil {
        return nil, trace.Wrap(err)
    }
    // try calling a test method via auth api:
    //
    // ??? in case of failure it never gets back here!!!
    dn, err := authClient.GetDomainName()
    if err != nil {
        return nil, trace.Wrap(err)
    }
    // success ? we're logged in!
    log.Infof("[Node] %s connected to the cluster '%s'", authUser, dn)
    return &service.Connector{Client: authClient, Identity: identity}, nil
}

// onExit allows individual services to register a callback function which will be
// called when Teleport Process is asked to exit. Usually services terminate themselves
// when the callback is called
func (p *EmbeddedNodeProcess) onExit(callback func(interface{})) {
    go func() {
        eventC := make(chan pervice.Event)
        p.WaitForEvent(service.TeleportExitEvent, eventC, make(chan struct{}))
        select {
            case event := <-eventC:
                callback(event.Payload)
        }
    }()
}

// RegisterWithAuthServer uses one time provisioning token obtained earlier
// from the server to get a pair of SSH keys signed by Auth server host
// certificate authority
func (p *EmbeddedNodeProcess) registerWithAuthServer(token string, role teleport.Role, eventName string) {
    var (
        cfg = p.config
        identityID = auth.IdentityID{Role: role, HostUUID: cfg.HostUUID}
        authClient *auth.TunClient = nil
    )

    log.Infof("registerWithAuthServer role %s cfg.HostUUID %s", role, cfg.HostUUID)

    // this means the server has not been initialized yet, we are starting
    // the registering client that attempts to connect to the auth server
    // and provision the keys
    p.RegisterFunc(func() error {
        retryTime := defaults.ServerHeartbeatTTL / 3
        for {
            connector, err := p.connectToAuthService(role)
            if err == nil {
                p.BroadcastEvent(pervice.Event{Name:eventName, Payload:connector})
                authClient = connector.Client
                return nil
            }
            if trace.IsConnectionProblem(err) {
                utils.Consolef(cfg.Console, "[%v] connecting to auth server: %v", role, err)
                time.Sleep(retryTime)
                continue
            }
            // We haven't connected yet, so we expect the token to exist
            // TODO when it's necessary to bring local connectivity on OSX, we'll do following
            // 1) bring in LocalAuth connectivity or
            // 2) combine PocketCoreTeleportProcess & PocketNodeTeleportProcess together

            // Auth server is remote, so we need a provisioning token.
            // !!! Since we need token only at the initialization, empty token check need to be here.!!!
            if token == "" {
                return trace.BadParameter("%v must join a cluster and needs a provisioning token", role)
            }
            log.Infof("[Node] %v joining the cluster with a token %v", role, token)
            err = auth.NodeRegister(cfg.NodeSSHPrivateKeyFile, cfg.NodeSSHCertificateFile, token, identityID, cfg.AuthServers)
            if err != nil {
                utils.Consolef(cfg.Console, "[%v] failed to join the cluster: %v", role, err)
                time.Sleep(retryTime)
            } else {
                utils.Consolef(cfg.Console, "[%v] Successfully registered with the cluster", role)
                continue
            }
        }
    })

    p.onExit(func(interface{}) {
        if authClient != nil {
            authClient.Close()
        }
    })
}

func (p *EmbeddedNodeProcess) StartNodeSSH() error {
    var (
        eventsC = make(chan pervice.Event)
        s *srv.Server = nil
    )

    // register & generate a signed ssh pub/prv key set
    p.registerWithAuthServer(p.config.Token, teleport.RoleNode, service.SSHIdentityEvent)
    p.WaitForEvent(service.SSHIdentityEvent, eventsC, make(chan struct{}))

    p.RegisterFunc(func() error {
        event := <-eventsC
        log.Infof("[SSH] received %v", &event)
        conn, ok := (event.Payload).(*service.Connector)
        if !ok {
            return trace.BadParameter("unsupported connector type: %T", event.Payload)
        }

        cfg := p.config

        limiter, err := limiter.NewLimiter(cfg.SSH.Limiter)
        if err != nil {
            return trace.Wrap(err)
        }

        s, err = srv.NewPocketSSHServer(cfg.SSH.Addr,
            cfg.Hostname,
            cfg.HostUUID,
            []ssh.Signer{conn.Identity.KeySigner},
            conn.Client,
            cfg.AdvertiseIP,
            srv.SetLimiter(limiter),
            srv.SetShell(cfg.SSH.Shell),
            srv.SetAuditLog(conn.Client),
            srv.SetSessionServer(conn.Client),
            srv.SetLabels(cfg.SSH.Labels, cfg.SSH.CmdLabels),
        )
        if err != nil {
            return trace.Wrap(err)
        }

        utils.Consolef(cfg.Console, "[SSH]   Service is starting on %v", cfg.SSH.Addr.Addr)
        if err := s.Start(); err != nil {
            utils.Consolef(cfg.Console, "[SSH]   Error: %v", err)
            return trace.Wrap(err)
        }
        s.Wait()
        log.Infof("[SSH] node service exited")
        return nil
    })

    // execute this when process is asked to exit:
    p.onExit(func(payload interface{}) {
        s.Close()
    })
    return nil
}

/// --- DOCKER ENGINE CERTIFICATE ACQUISITION --- ///
// requestSignedEngineCertificateWithAuthServer uses one time provisioning token obtained earlier from the server to get
// a pair of Docker Engine keys signed by Auth server host certificate authority
func (p *EmbeddedNodeProcess) requestEngineCertWithAuthServer(role teleport.Role, onSucessAct func() error) error {
    var (
        cfg = p.config
        token = p.config.Token
        eventsC = make(chan pervice.Event)
    )
    // Auth server is remote, so we need a provisioning token
    if token == "" {
        return trace.BadParameter("%v must request a signed certificate and needs a provisioning token", role)
    }

    log.Infof("[%v] requestEngineCertWithAuthServer %v", role, token)

    // we're to wait until SSH successfully connects to master
    p.WaitForEvent(service.SSHIdentityEvent, eventsC, make(chan struct{}))

    // this means the server has not been initialized yet, we are starting
    // the registering client that attempts to connect to the auth server
    // and provision the keys
    p.RegisterFunc(func() error {
        var (
            retryTime = defaults.ServerHeartbeatTTL / 3
            err error = nil
        )
        // we're to wait until SSH successfully connects to master
        _ = <-eventsC
        log.Infof("[Node] %v requesting a signed certificate with a token %v | UUID %v : ", role, token, cfg.HostUUID)
        // start request signed certificate
        for {
            err = auth.RequestSignedCertificate(
                &auth.PocketCertParam{
                    AuthServers:          cfg.AuthServers,
                    Role:                 role,
                    Hostname:             cfg.Hostname,
                    HostUUID:             cfg.HostUUID,
                    AuthToken:            token,
                    AuthorityCertFile:    cfg.AuthorityCertFile,
                    NodeEngineCertFile:   cfg.NodeEngineCertFile,
                    NodeEngineKeyFile:    cfg.NodeEngineKeyFile,
                })
            if err != nil {
                utils.Consolef(cfg.Console, "[%v] failed to receive a signed certificate : %v", role, err)
                time.Sleep(retryTime)
            } else {
                if onSucessAct != nil {
                    // we'll ignore errors
                    onSucessAct()
                }
                utils.Consolef(cfg.Console, "[%v] Successfully received a signed certificate & finished subsequent action", role)
                return nil
            }
        }
    })

    return nil
}

// generates a signed certificate & private key for docker/registry
func (p *EmbeddedNodeProcess) AcquireEngineCertificate(onSucessAct func() error) error {
    p.requestEngineCertWithAuthServer(teleport.RoleNode, onSucessAct)
    return nil
}