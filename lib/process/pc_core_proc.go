// +build darwin
package process

import (
    "crypto/tls"
    "fmt"
    "net"
    //"net/http"
    "path/filepath"
    "os"
    "sync"
    "time"
    "io/ioutil"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/utils"
    "github.com/gravitational/teleport/lib/auth"
    "github.com/gravitational/teleport/lib/auth/native"
    "github.com/gravitational/teleport/lib/config"
    "github.com/gravitational/teleport/lib/defaults"
    "github.com/gravitational/teleport/lib/events"
    "github.com/gravitational/teleport/lib/session"
    "github.com/gravitational/teleport/lib/limiter"
    "github.com/gravitational/teleport/lib/services"
    "github.com/gravitational/teleport/lib/backend"
    "github.com/gravitational/teleport/lib/backend/boltbk"
    "github.com/gravitational/teleport/lib/backend/sqlitebk"
    "github.com/gravitational/teleport/lib/reversetunnel"
    "github.com/gravitational/teleport/lib/srv"
    "github.com/gravitational/teleport/lib/service"
    //"github.com/gravitational/teleport/lib/web"

    log "github.com/Sirupsen/logrus"
    "github.com/gravitational/trace"
    "github.com/pborman/uuid"
    "golang.org/x/crypto/ssh"
)

// NewTeleport takes the daemon configuration, instantiates all required services
// and starts them under a supervisor, returning the supervisor object
func NewCoreProcess(cfg *service.PocketConfig) (*PocketCoreProcess, error) {
    if err := service.ValidateCoreConfig(cfg); err != nil {
        return nil, trace.Wrap(err, "Configuration error")
    }

    // create the data directory if it's missing
    _, err := os.Stat(cfg.DataDir)
    if os.IsNotExist(err) {
        err := os.MkdirAll(cfg.DataDir, os.ModeDir|0700)
        if err != nil {
            return nil, trace.Wrap(err)
        }
    }

    // if there's no host uuid initialized yet, try to read one from the
    // one of the identities
    cfg.HostUUID, err = utils.ReadHostUUID(cfg.DataDir)
    if err != nil {
/*
        TODO : need to look into IsNotFound Error to see what really happens
        if !trace.IsNotFound(err) {
            return nil, trace.Wrap(err)
        }
*/
        if len(cfg.Identities) != 0 {
            cfg.HostUUID = cfg.Identities[0].ID.HostUUID
            log.Infof("[INIT] taking host uuid from first identity: %v", cfg.HostUUID)
        } else {
            cfg.HostUUID = uuid.New()
            log.Infof("[INIT] generating new host UUID: %v", cfg.HostUUID)
        }
        if err := utils.WriteHostUUID(cfg.DataDir, cfg.HostUUID); err != nil {
            return nil, trace.Wrap(err)
        }
    }

    // if user started auth and another service (without providing the auth address for
    // that service, the address of the in-process auth will be used
    if cfg.Auth.Enabled && len(cfg.AuthServers) == 0 {
        cfg.AuthServers = []utils.NetAddr{cfg.Auth.SSHAddr}
    }

    // if user did not provide auth domain name, use this host UUID
    if cfg.Auth.Enabled && cfg.Auth.DomainName == "" {
        cfg.Auth.DomainName = cfg.HostUUID
    }

    // try to login into the auth service:

    // if there are no certificates, use self signed
    process := &PocketCoreProcess{
        Supervisor: service.NewSupervisor(),
        Config:     cfg,
    }

    if cfg.Keygen == nil {
        cfg.Keygen = native.New()
    }
    if err := process.initAuthService(cfg.Keygen); err != nil {
        return nil, trace.Wrap(err)
    }
    if err := process.initProxy(); err != nil {
        return nil, err
    }
    return process, nil
}

// TeleportProcess structure holds the state of the Teleport daemon, controlling
// execution and configuration of the teleport services: ssh, auth and proxy.
type PocketCoreProcess struct {
    sync.Mutex
    service.Supervisor
    Config *service.PocketConfig
    // localAuth has local auth server listed in case if this process
    // has started with auth server role enabled
    localAuth *auth.AuthServer
}

func (p *PocketCoreProcess) findStaticIdentity(id auth.IdentityID) (*auth.Identity, error) {
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
func (p *PocketCoreProcess) connectToAuthService(role teleport.Role) (*service.Connector, error) {
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

func (p *PocketCoreProcess) setLocalAuth(a *auth.AuthServer) {
    p.Lock()
    defer p.Unlock()
    p.localAuth = a
}

func (p *PocketCoreProcess) getLocalAuth() (a *auth.AuthServer) {
    p.Lock()
    defer p.Unlock()
    return p.localAuth
}

// onExit allows individual services to register a callback function which will be
// called when Teleport Process is asked to exit. Usually services terminate themselves
// when the callback is called
func (p *PocketCoreProcess) onExit(callback func(interface{})) {
    go func() {
        eventC := make(chan service.Event)
        p.WaitForEvent(service.TeleportExitEvent, eventC, make(chan struct{}))
        select {
        case event := <-eventC:
            callback(event.Payload)
        }
    }()
}

// initAuthStorage initializes the storage backend for the auth. service
func (p *PocketCoreProcess) initAuthStorage() (backend.Backend, error) {
    cfg := &p.Config.Auth
    var bk backend.Backend
    var err error

    switch cfg.KeysBackend.Type {
    case teleport.BoltBackendType:
        bk, err = boltbk.FromJSON(cfg.KeysBackend.Params)
    case teleport.SQLiteBackendType:
        // TODO : we need to pass sqlite instance instead of json param
        bk, err = sqlitebk.FromJSON(cfg.KeysBackend.Params)
    default:
        return nil, trace.Errorf("unsupported backend type: %v", cfg.KeysBackend.Type)
    }
    if err != nil {
        return nil, trace.Wrap(err)
    }

    return bk, nil
}

// initAuthService can be called to initialize auth server service
func (p *PocketCoreProcess) initAuthService(authority auth.Authority) error {
    var (
        askedToExit = false
        err         error
    )
    cfg := p.Config
    // Initialize the storage back-ends for keys, events and records
    b, err := p.initAuthStorage()
    if err != nil {
        return trace.Wrap(err)
    }

    // create the audit log, which will be consuming (and recording) all events
    // and record sessions
    var auditLog events.IAuditLog
    if cfg.Auth.NoAudit {
        auditLog = &events.DiscardAuditLog{}
        log.Warn("the audit and session recording are turned off")
    } else {
        auditLog, err = events.NewAuditLog(filepath.Join(cfg.DataDir, "log"))
        if err != nil {
            return trace.Wrap(err)
        }
    }

    // first, create the AuthServer
    authServer, identity, err := auth.Init(auth.InitConfig{
        Backend:         b,
        Authority:       authority,
        DomainName:      cfg.Auth.DomainName,
        AuthServiceName: cfg.Hostname,
        DataDir:         cfg.DataDir,
        HostUUID:        cfg.HostUUID,
        Authorities:     cfg.Auth.Authorities,
        ReverseTunnels:  cfg.ReverseTunnels,
        OIDCConnectors:  cfg.OIDCConnectors,
        Trust:           cfg.Trust,
        Lock:            cfg.Lock,
        Presence:        cfg.Presence,
        Provisioner:     cfg.Provisioner,
        Identity:        cfg.Identity,
        StaticTokens:    cfg.Auth.StaticTokens,
    }, cfg.SeedConfig)
    if err != nil {
        return trace.Wrap(err)
    }
    p.setLocalAuth(authServer)

    // second, create the API Server: it's actually a collection of API servers,
    // each serving requests for a "role" which is assigned to every connected
    // client based on their certificate (user, server, admin, etc)
    sessionService, err := session.New(b)
    if err != nil {
        return trace.Wrap(err)
    }
    apiConf := &auth.APIConfig{
        AuthServer:        authServer,
        SessionService:    sessionService,
        PermissionChecker: auth.NewStandardPermissions(),
        AuditLog:          auditLog,
        CertSigner:        p.Config.CaSigner,
    }

    limiter, err := limiter.NewLimiter(cfg.Auth.Limiter)
    if err != nil {
        return trace.Wrap(err)
    }

    // Register an SSH endpoint which is used to create an SSH tunnel to send HTTP
    // requests to the Auth API
    var authTunnel *auth.AuthTunnel
    p.RegisterFunc(func() error {
        utils.Consolef(cfg.Console, "[AUTH]  Auth service is starting on %v", cfg.Auth.SSHAddr.Addr)
        authTunnel, err = auth.NewTunnel(
            cfg.Auth.SSHAddr,
            identity.KeySigner,
            apiConf,
            auth.SetLimiter(limiter),
        )
        if err != nil {
            utils.Consolef(cfg.Console, "[AUTH] Error: %v", err)
            return trace.Wrap(err)
        }
        if err := authTunnel.Start(); err != nil {
            if askedToExit {
                log.Infof("[AUTH] Auth Tunnel exited")
                return nil
            }
            utils.Consolef(cfg.Console, "[AUTH] Error: %v", err)
            return trace.Wrap(err)
        }
        return nil
    })

    p.RegisterFunc(func() error {
        // Heart beat auth server presence, this is not the best place for this
        // logic, consolidate it into auth package later
        connector, err := p.connectToAuthService(teleport.RoleAdmin)
        if err != nil {
            return trace.Wrap(err)
        }
        // External integrations rely on this event:
        p.BroadcastEvent(service.Event{Name: service.AuthIdentityEvent, Payload: connector})
        p.onExit(func(payload interface{}) {
            connector.Client.Close()
        })
        return nil
    })

    p.RegisterFunc(func() error {
        srv := services.Server{
            ID:       p.Config.HostUUID,
            Addr:     cfg.Auth.SSHAddr.Addr,
            Hostname: p.Config.Hostname,
        }
        host, port, err := net.SplitHostPort(srv.Addr)
        // advertise-ip is explicitly set:
        if p.Config.AdvertiseIP != nil {
            if err != nil {
                return trace.Wrap(err)
            }
            srv.Addr = fmt.Sprintf("%v:%v", p.Config.AdvertiseIP.String(), port)
        } else {
            // advertise-ip is not set, while the CA is listening on 0.0.0.0? lets try
            // to guess the 'advertise ip' then:
            if net.ParseIP(host).IsUnspecified() {
                ip, err := utils.GuessHostIP()
                if err != nil {
                    log.Warn(err)
                } else {
                    srv.Addr = net.JoinHostPort(ip.String(), port)
                }
            }
            log.Warnf("advertise_ip is not set for this auth server!!! Trying to guess the IP this server can be reached at: %v", srv.Addr)
        }
        // immediately register, and then keep repeating in a loop:
        for !askedToExit {
            err := authServer.UpsertAuthServer(srv, defaults.ServerHeartbeatTTL)
            if err != nil {
                log.Warningf("failed to announce presence: %v", err)
            }
            sleepTime := defaults.ServerHeartbeatTTL/2 + utils.RandomDuration(defaults.ServerHeartbeatTTL/10)
            time.Sleep(sleepTime)
        }
        log.Infof("[AUTH] heartbeat to other auth servers exited")
        return nil
    })

    // execute this when process is asked to exit:
    p.onExit(func(payload interface{}) {
        askedToExit = true
        authTunnel.Close()
        log.Infof("[AUTH] auth service exited")
    })
    return nil
}

// initSelfSignedHTTPSCert generates and self-signs a TLS key+cert pair for https connection
// to the proxy server.
func initSelfSignedHTTPSCert(cfg *service.PocketConfig) (err error) {
    log.Warningf("[CONFIG] NO TLS Keys provided, using self signed certificate")

    keyPath := filepath.Join(cfg.DataDir, defaults.SelfSignedKeyPath)
    certPath := filepath.Join(cfg.DataDir, defaults.SelfSignedCertPath)

    cfg.Proxy.TLSKey = keyPath
    cfg.Proxy.TLSCert = certPath

    // return the existing pair if they ahve already been generated:
    _, err = tls.LoadX509KeyPair(certPath, keyPath)
    if err == nil {
        return nil
    }
    if !os.IsNotExist(err) {
        return trace.Wrap(err, "unrecognized error reading certs")
    }
    log.Warningf("[CONFIG] Generating self signed key and cert to %v %v", keyPath, certPath)

    creds, err := utils.GenerateSelfSignedCert([]string{cfg.Hostname, "localhost"})
    if err != nil {
        return trace.Wrap(err)
    }

    if err := ioutil.WriteFile(keyPath, creds.PrivateKey, 0600); err != nil {
        return trace.Wrap(err, "error writing key PEM")
    }
    if err := ioutil.WriteFile(certPath, creds.Cert, 0600); err != nil {
        return trace.Wrap(err, "error writing key PEM")
    }
    return nil
}

// initProxy gets called if teleport runs with 'proxy' role enabled.
// this means it will do two things:
//    1. serve a web UI
//    2. proxy SSH connections to nodes running with 'node' role
//    3. take care of revse tunnels
func (p *PocketCoreProcess) initProxy() error {
    // TODO : (11/28/2016) TLS Certificate should be generated in pc-core context initiation
    // if no TLS key was provided for the web UI, generate a self signed cert
    if p.Config.Proxy.TLSKey == "" && !p.Config.Proxy.DisableWebUI {
        err := initSelfSignedHTTPSCert(p.Config)
        if err != nil {
            return trace.Wrap(err)
        }
    }

    p.RegisterWithAuthServer(p.Config.Token, teleport.RoleProxy, service.ProxyIdentityEvent)

    p.RegisterFunc(func() error {
        eventsC := make(chan service.Event)
        p.WaitForEvent(service.ProxyIdentityEvent, eventsC, make(chan struct{}))

        event := <-eventsC
        log.Infof("[SSH] received %v", &event)
        conn, ok := (event.Payload).(*service.Connector)
        if !ok {
            return trace.BadParameter("unsupported connector type: %T", event.Payload)
        }
        return trace.Wrap(p.initProxyEndpoint(conn))
    })
    return nil
}

// RegisterWithAuthServer uses one time provisioning token obtained earlier
// from the server to get a pair of SSH keys signed by Auth server host
// certificate authority
func (p *PocketCoreProcess) RegisterWithAuthServer(token string, role teleport.Role, eventName string) {
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
            TODO : need to look into IsNotFound Error to see what really happens
            if !trace.IsNotFound(err) {
                return trace.Wrap(err)
            }
*/
            //  we haven't connected yet, so we expect the token to exist
            if p.getLocalAuth() != nil {
                // Auth service is on the same host, no need to go though the invitation
                // procedure
                log.Debugf("[Node] this server has local Auth server started, using it to add role to the cluster")
                err = auth.LocalRegister(cfg.DataDir, identityID, p.getLocalAuth())
            } else {
                // Auth server is remote, so we need a provisioning token
                if token == "" {
                    return trace.BadParameter("%v must join a cluster and needs a provisioning token", role)
                }
                log.Infof("[Node] %v joining the cluster with a token %v", role, token)
                err = auth.Register(cfg.DataDir, token, identityID, cfg.AuthServers)
            }
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

func (p *PocketCoreProcess) initProxyEndpoint(conn *service.Connector) error {
    var (
        askedToExit = true
        err         error
    )
    cfg := p.Config
    proxyLimiter, err := limiter.NewLimiter(cfg.Proxy.Limiter)
    if err != nil {
        return trace.Wrap(err)
    }

    reverseTunnelLimiter, err := limiter.NewLimiter(cfg.Proxy.Limiter)
    if err != nil {
        return trace.Wrap(err)
    }

    tsrv, err := reversetunnel.NewServer(
        cfg.Proxy.ReverseTunnelListenAddr,
        []ssh.Signer{conn.Identity.KeySigner},
        conn.Client,
        reversetunnel.SetLimiter(reverseTunnelLimiter),
        reversetunnel.DirectSite(conn.Identity.Cert.Extensions[utils.CertExtensionAuthority], conn.Client),
    )
    if err != nil {
        return trace.Wrap(err)
    }

    SSHProxy, err := srv.New(cfg.Proxy.SSHAddr,
        cfg.Hostname,
        []ssh.Signer{conn.Identity.KeySigner},
        conn.Client,
        cfg.DataDir,
        nil,
        srv.SetLimiter(proxyLimiter),
        srv.SetProxyMode(tsrv),
        srv.SetSessionServer(conn.Client),
        srv.SetAuditLog(conn.Client),
    )
    if err != nil {
        return trace.Wrap(err)
    }

    // Register reverse tunnel agents pool
    agentPool, err := reversetunnel.NewAgentPool(reversetunnel.AgentPoolConfig{
        HostUUID:    conn.Identity.ID.HostUUID,
        Client:      conn.Client,
        HostSigners: []ssh.Signer{conn.Identity.KeySigner},
    })
    if err != nil {
        return trace.Wrap(err)
    }

    // register SSH reverse tunnel server that accepts connections
    // from remote teleport nodes
    p.RegisterFunc(func() error {
        utils.Consolef(cfg.Console, "[PROXY] Reverse tunnel service is starting on %v", cfg.Proxy.ReverseTunnelListenAddr.Addr)
        if err := tsrv.Start(); err != nil {
            utils.Consolef(cfg.Console, "[PROXY] Error: %v", err)
            return trace.Wrap(err)
        }
        // notify parties that we've started reverse tunnel server
        p.BroadcastEvent(service.Event{Name: service.ProxyReverseTunnelServerEvent, Payload: tsrv})
        tsrv.Wait()
        if askedToExit {
            log.Infof("[PROXY] Reverse tunnel exited")
        }
        return nil
    })

    // Register web proxy server
    var webListener net.Listener
    // TODO : (03/14/2017) this is now removed from user login flow. Delete this when it is fine to do so
/*
    p.RegisterFunc(func() error {
        utils.Consolef(cfg.Console, "[PROXY] Web proxy service is starting on %v", cfg.Proxy.WebAddr.Addr)
        webHandler, err := web.NewPocketHandler(
            web.Config{
                Proxy:       tsrv,
                AssetsDir:   cfg.Proxy.AssetsDir,
                AuthServers: cfg.AuthServers[0],
                DomainName:  cfg.Hostname,
                ProxyClient: conn.Client,
                DisableUI:   cfg.Proxy.DisableWebUI,
            })
        if err != nil {
            utils.Consolef(cfg.Console, "[PROXY] error in starting the web server: %v", err)
            return trace.Wrap(err)
        }
        defer webHandler.Close()

        proxyLimiter.WrapHandle(webHandler)
        p.BroadcastEvent(service.Event{Name: service.ProxyWebServerEvent, Payload: webHandler})

        log.Infof("[PROXY] init TLS listeners")
        webListener, err = utils.ListenTLS(
            cfg.Proxy.WebAddr.Addr,
            cfg.Proxy.TLSCert,
            cfg.Proxy.TLSKey)
        if err != nil {
            return trace.Wrap(err)
        }
        if err = http.Serve(webListener, proxyLimiter); err != nil {
            if askedToExit {
                log.Infof("[PROXY] web server exited")
                return nil
            }
            log.Error(err)
        }
        return nil
    })
*/

    // Register ssh proxy server
    p.RegisterFunc(func() error {
        utils.Consolef(cfg.Console, "[PROXY] SSH proxy service is starting on %v", cfg.Proxy.SSHAddr.Addr)
        if err := SSHProxy.Start(); err != nil {
            if askedToExit {
                log.Infof("[PROXY] SSH proxy exited")
                return nil
            }
            utils.Consolef(cfg.Console, "[PROXY] Error: %v", err)
            return trace.Wrap(err)
        }
        return nil
    })

    p.RegisterFunc(func() error {
        log.Infof("[PROXY] starting reverse tunnel agent pool")
        if err := agentPool.Start(); err != nil {
            log.Fatalf("failed to start: %v", err)
            return trace.Wrap(err)
        }
        agentPool.Wait()
        return nil
    })

    // execute this when process is asked to exit:
    p.onExit(func(payload interface{}) {
        tsrv.Close()
        SSHProxy.Close()
        agentPool.Stop()
        if webListener != nil {
            webListener.Close()
        }
        log.Infof("[PROXY] proxy service exited")
    })
    return nil
}

// --- Core Process Test Starter --- //

func StartCoreProcessTest(cfg *service.PocketConfig, debug bool) error {
    // add static tokens
    for _, token := range []config.StaticToken{"node:d52527f9-b260-41d0-bb5a-e23b0cfe0f8f", "node:c9s93fd9-3333-91d3-9999-c9s93fd98f43"} {
        roles, tokenValue, err := token.Parse()
        if err != nil {
            log.Error(err.Error())
            return trace.Wrap(err)
        }
        cfg.Auth.StaticTokens = append(cfg.Auth.StaticTokens, services.ProvisionToken{Token: tokenValue, Roles: roles, Expires: time.Unix(0, 0)})
    }

    // add temporary token
    srv, err := NewCoreProcess(cfg)
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