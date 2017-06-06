package srv

import (
    "net"
    "sync"

    "github.com/gravitational/teleport"
    "github.com/gravitational/teleport/lib/auth"
    "github.com/gravitational/teleport/lib/limiter"
    "github.com/gravitational/teleport/lib/sshutils"
    "github.com/gravitational/teleport/lib/utils"

    "github.com/gravitational/trace"
    "golang.org/x/crypto/ssh"
)

// New returns an unstarted server
func NewPocketSSHServer(
    addr utils.NetAddr,
    hostname string,
    hostUUID string,
    signers []ssh.Signer,
    authService auth.AccessPoint,
    advertiseIP net.IP,
    options ...ServerOption) (*Server, error) {

    s := &Server{
        addr:        addr,
        authService: authService,
        resolver:    &backendResolver{authService: authService},
        hostname:    hostname,
        labelsMutex: &sync.Mutex{},
        advertiseIP: advertiseIP,
        uuid:        hostUUID,
        closer:      utils.NewCloseBroadcaster(),
    }

    var err error = nil
    s.limiter, err = limiter.NewLimiter(limiter.LimiterConfig{})
    if err != nil {
        return nil, trace.Wrap(err)
    }
    s.certChecker = ssh.CertChecker{IsAuthority: s.isAuthority}

    for _, o := range options {
        if err := o(s); err != nil {
            return nil, trace.Wrap(err)
        }
    }

    var component string
    if s.proxyMode {
        component = teleport.ComponentProxy
    } else {
        component = teleport.ComponentNode
    }

    s.reg = newSessionRegistry(s)
    srv, err := sshutils.NewServer(
        component,
        addr, s, signers,
        sshutils.AuthMethods{PublicKey: s.keyAuth},
        sshutils.SetLimiter(s.limiter),
        sshutils.SetRequestHandler(s))
    if err != nil {
        return nil, trace.Wrap(err)
    }
    s.srv = srv
    return s, nil
}
