package process

import (
    "time"
    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/auth"
    "github.com/gravitational/teleport/lib/defaults"
    "github.com/gravitational/teleport/lib/limiter"
    "github.com/gravitational/teleport/lib/srv"
    "github.com/gravitational/teleport/lib/service"
    "github.com/gravitational/teleport/lib/utils"

    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/trace"
    "golang.org/x/crypto/ssh"
)

const (
    // SignedCertificateEvent is generated when a signed certificate is issued from auth server
    SignedCertificateIssuedEvent = "RequestSignedCertificateIssued"
)

// NewTeleport takes the daemon configuration, instantiates all required services
// and starts them under a supervisor, returning the supervisor object
func NewNodeProcess(cfg *service.PocketConfig) (*PocketNodeProcess, error) {
    var err error
    process := &PocketNodeProcess{
        Supervisor: service.NewSupervisor(),
        Config:     cfg,
    }

    err = process.initSSH();
    if err != nil {
        return nil, err
    }

    return process, nil
}

// TeleportProcess structure holds the state of the Teleport daemon, controlling
// execution and configuration of the teleport services: ssh, auth and proxy.
type PocketNodeProcess struct {
    service.Supervisor
    Config *service.PocketConfig
}

func (p *PocketNodeProcess) Close() error {
    p.BroadcastEvent(service.Event{Name: service.TeleportExitEvent})
    return nil
}

func (p *PocketNodeProcess) findStaticIdentity(id auth.IdentityID) (*auth.Identity, error) {
    for i := range p.Config.Identities {
        identity := p.Config.Identities[i]
        if identity.ID.Equals(id) {
            return identity, nil
        }
    }
    return nil, trace.NotFound("identity %v not found", &id)
}

// connectToAuthService attempts to login into the auth servers specified in the
// configuration. Returns 'true' if successful
func (p *PocketNodeProcess) connectToAuthService(role teleport.Role) (*service.Connector, error) {
    id := auth.IdentityID{HostUUID: p.Config.HostUUID, Role: role}
    identity, err := auth.ReadIdentity(p.Config.DataDir, id)
    if err != nil {
        if trace.IsNotFound(err) {
            // try to locate static identity provide in the file
            identity, err = p.findStaticIdentity(id)
            if err != nil {
                return nil, trace.Wrap(err)
            }
            log.Infof("found static identity %v in the config file, writing to disk", &id)
            if err = auth.WriteIdentity(p.Config.DataDir, identity); err != nil {
                return nil, trace.Wrap(err)
            }
        } else {
            return nil, trace.Wrap(err)
        }
    }

    authUser := identity.Cert.ValidPrincipals[0]
    authClient, err := auth.NewTunClient(
        string(role),
        p.Config.AuthServers,
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
func (p *PocketNodeProcess) onExit(callback func(interface{})) {
    go func() {
        eventC := make(chan service.Event)
        p.WaitForEvent(service.TeleportExitEvent, eventC, make(chan struct{}))
        select {
        case event := <-eventC:
            callback(event.Payload)
        }
    }()
}

func (p *PocketNodeProcess) initSSH() error {
    eventsC := make(chan service.Event)

    // register & generate a signed ssh pub/prv key set
    p.RegisterWithAuthServer(p.Config.Token, teleport.RoleNode, service.SSHIdentityEvent)
    p.WaitForEvent(service.SSHIdentityEvent, eventsC, make(chan struct{}))

    // generates a signed certificate & private key for docker/registry
    p.RequestSignedCertificateWithAuthServer(p.Config.Token, teleport.RoleNode, SignedCertificateIssuedEvent)
    p.WaitForEvent(SignedCertificateIssuedEvent, eventsC, make(chan struct{}))

    var s *srv.Server
    p.RegisterFunc(func() error {
        event := <-eventsC
        log.Infof("[SSH] received %v", &event)
        conn, ok := (event.Payload).(*service.Connector)
        if !ok {
            return trace.BadParameter("unsupported connector type: %T", event.Payload)
        }

        cfg := p.Config

        limiter, err := limiter.NewLimiter(cfg.SSH.Limiter)
        if err != nil {
            return trace.Wrap(err)
        }

        s, err = srv.New(cfg.SSH.Addr,
            cfg.Hostname,
            []ssh.Signer{conn.Identity.KeySigner},
            conn.Client,
            cfg.DataDir,
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

// RegisterWithAuthServer uses one time provisioning token obtained earlier
// from the server to get a pair of SSH keys signed by Auth server host
// certificate authority
func (p *PocketNodeProcess) RegisterWithAuthServer(token string, role teleport.Role, eventName string) {
    cfg := p.Config
    identityID := auth.IdentityID{Role: role, HostUUID: cfg.HostUUID}

    log.Infof("RegisterWithAuthServer role %s cfg.HostUUID %s", role, cfg.HostUUID)

    // this means the server has not been initialized yet, we are starting
    // the registering client that attempts to connect to the auth server
    // and provision the keys
    var authClient *auth.TunClient
    p.RegisterFunc(func() error {
        retryTime := defaults.ServerHeartbeatTTL / 3
        for {
            connector, err := p.connectToAuthService(role)
            if err == nil {
                p.BroadcastEvent(service.Event{Name: eventName, Payload: connector})
                authClient = connector.Client
                return nil
            }
            if trace.IsConnectionProblem(err) {
                utils.Consolef(cfg.Console, "[%v] connecting to auth server: %v", role, err)
                time.Sleep(retryTime)
                continue
            }
/*
            //TODO : need to look into IsNotFound Error to see what really happens
            if !trace.IsNotFound(err) {
                return trace.Wrap(err)
            }
*/
            // We haven't connected yet, so we expect the token to exist
            // TODO when it's necessary to bring local connectivity on OSX, we'll do following
            // 1) bring in LocalAuth connectivity or
            // 2) combine PocketCoreTeleportProcess & PocketNodeTeleportProcess together

            // Auth server is remote, so we need a provisioning token
            if token == "" {
                return trace.BadParameter("%v must join a cluster and needs a provisioning token", role)
            }
            log.Infof("[Node] %v joining the cluster with a token %v", role, token)
            err = auth.Register(cfg.DataDir, token, identityID, cfg.AuthServers)
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

// RequestSignedCertificateWithAuthServer uses one time provisioning token obtained earlier
// from the server to get a pair of SSH keys signed by Auth server host
// certificate authority
func (p *PocketNodeProcess) RequestSignedCertificateWithAuthServer(token string, role teleport.Role, eventName string) {
    var (
        cfg = p.Config
        token = p.Config.Token
        authClient *auth.TunClient = nil
    )

    log.Infof("RequestSignedCertificateWithAuthServer role %s cfg.HostUUID %s", role, cfg.HostUUID)

    // this means the server has not been initialized yet, we are starting
    // the registering client that attempts to connect to the auth server
    // and provision the keys
    p.RegisterFunc(func() error {
        retryTime := defaults.ServerHeartbeatTTL / 3
        for {
            connector, err := p.connectToAuthService(role)
            if err == nil {
                p.BroadcastEvent(service.Event{Name: eventName, Payload: connector})
                authClient = connector.Client
                return nil
            }
            if trace.IsConnectionProblem(err) {
                utils.Consolef(cfg.Console, "[%v] connecting to auth server: %v", role, err)
                time.Sleep(retryTime)
                continue
            }
/*
            //TODO : need to look into IsNotFound Error to see what really happens.
            if !trace.IsNotFound(err) {
                return trace.Wrap(err)
            }
*/
            // Auth server is remote, so we need a provisioning token
            if token == "" {
                return trace.BadParameter("%v must request a signed certificate and needs a provisioning token", role)
            }
            log.Infof("[Node] %v requesting a signed certificate with a token %v", role, token)
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
                utils.Consolef(cfg.Console, "[%v] Successfully received a signed certificate", role)
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
